#!/bin/bash
# packaging/vm.sh: test the packages on real distribution kernels in KVM
# virtual machines (libvirt, cloud images; run as a user who may sudo).
#
#   packaging/vm.sh up NAME IMAGE OSINFO   boot NAME from a cloud image in
#                                          /var/lib/libvirt/images (copy on write);
#                                          VM_BOOT=uefi: UEFI firmware (efi_pstore)
#   packaging/vm.sh test NAME [WHAT]       install dist/'s packages and test;
#                                          WHAT: service ebpf e2e truth tls sos (default all);
#                                          CLIFR_TEST_RECORDER_ARGS: extra recorder
#                                          options for e2e and truth
#   packaging/vm.sh ssh NAME [COMMAND]     a shell or a command on NAME
#   packaging/vm.sh down NAME              delete NAME and its disks
#
# Build first: packaging/build.sh, then packaging/vm.sh bins (test binaries;
# DOCKER="sudo docker" as for build.sh).
set -euo pipefail
cd "$(dirname "$0")/.." >/dev/null # quiet when CDPATH is set
images=/var/lib/libvirt/images
cache=$PWD/dist/.cache/vm
key=$cache/id_ed25519
mkdir -p "$cache"
[ -f "$key" ] || ssh-keygen -q -t ed25519 -N '' -f "$key" -C clifr-vm-test

ip() {
	for _ in $(seq 1 90); do
		a=$(sudo virsh domifaddr "clifr-$1" --source lease 2>/dev/null | awk '/ipv4/ {sub("/.*", "", $4); print $4; exit}')
		[ -n "$a" ] && { echo "$a"; return; }
		sleep 2
	done
	echo "no address for clifr-$1" >&2
	return 1
}
sshopts=(-i "$key" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=5)
on() { local n=$1; shift; ssh "${sshopts[@]}" "tester@$(ip "$n")" "$@"; }

case ${1:-} in
bins)
	# Test binaries and the helpers they would otherwise build with Go.
	b=dist/vmtest
	rm -rf $b && mkdir -p $b/bin
	CGO_ENABLED=0 go test -c -tags e2e -o $b/e2e.test ./test/e2e
	# The truth test links DuckDB: built like the package's clifr (glibc 2.28).
	${DOCKER:-docker} run --rm -v "$PWD/dist/.cache/go:/usr/local/go:ro" -v "$(go env GOMODCACHE):/gomod:ro" -v "$PWD:/src" \
		-e GOMODCACHE=/gomod -e GOFLAGS=-mod=mod -e GOCACHE=/src/dist/.cache/gocache -e GOTOOLCHAIN=local -e GOPROXY=off \
		-w /src rockylinux:8 bash -euc "
			dnf -q -y install gcc-toolset-13-gcc-c++ >/dev/null
			source /opt/rh/gcc-toolset-13/enable
			CGO_ENABLED=1 /usr/local/go/bin/go test -c -buildvcs=false -tags truth -o $b/truth.test ./test/truth
			chown -R $(stat -c %u:%g .) dist"
	CGO_ENABLED=0 go build -o $b/bin/load ./bench/load
	CGO_ENABLED=0 go build -o $b/bin/truthproc ./test/truth/truthproc
	cp dist/clifrd dist/clifr $b/bin/ # the packages' binaries (clifr for glibc 2.28)
	ls -la $b $b/bin
	;;
up)
	n=$2 image=$3 osinfo=$4
	disk=$images/clifr-$n.qcow2 seed=$images/clifr-$n-seed.iso
	sudo qemu-img create -q -f qcow2 -F qcow2 -b "$images/$image" "$disk" 40G
	cat >"$cache/user-data" <<UD
#cloud-config
hostname: clifr-$n
users:
  - name: tester
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    ssh_authorized_keys: [$(cat "$key.pub")]
UD
	echo "instance-id: clifr-$n" >"$cache/meta-data"
	sudo cloud-localds "$seed" "$cache/user-data" "$cache/meta-data"
	sudo virt-install -q --name "clifr-$n" --memory 8192 --vcpus 4 --osinfo "$osinfo" \
		--disk "path=$disk,format=qcow2" --disk "path=$seed,device=cdrom" --import \
		--network network=default --graphics none --noautoconsole ${VM_BOOT:+--boot $VM_BOOT}
	a=$(ip "$n")
	for _ in $(seq 1 60); do on "$n" true 2>/dev/null && break; sleep 3; done
	on "$n" 'cloud-init status --wait >/dev/null 2>&1; uname -r; cat /etc/os-release | grep PRETTY'
	echo "clifr-$n is up at $a"
	;;
ssh)
	n=$2; shift 2
	on "$n" "$@"
	;;
test)
	n=$2; shift 2
	what=${*:-service ebpf e2e truth tls sos}
	a=$(ip "$n")
	on "$n" 'rm -rf ~/t && mkdir -p ~/t/pkg ~/t/test/e2e ~/t/test/truth ~/t/bench/results'
	scp -q "${sshopts[@]}" dist/*.deb dist/*.rpm "tester@$a:t/pkg/"
	scp -q -r "${sshopts[@]}" dist/vmtest/bin dist/vmtest/e2e.test dist/vmtest/truth.test "tester@$a:t/"
	scp -q "${sshopts[@]}" packaging/vm-test.sh "tester@$a:t/"
	# CLIFR_TEST_RECORDER_ARGS (e.g. "--events proc_connector") reaches the
	# e2e and truth tests' recorder.
	on "$n" "sudo CLIFR_TEST_RECORDER_ARGS='${CLIFR_TEST_RECORDER_ARGS:-}' bash ~/t/vm-test.sh $what" 2>&1 | tee "$cache/test-$n.log"
	;;
down)
	n=$2
	sudo virsh destroy "clifr-$n" >/dev/null 2>&1 || true
	sudo virsh undefine "clifr-$n" --remove-all-storage --nvram >/dev/null 2>&1 || true # --nvram: UEFI VMs
	sudo rm -f "$images/clifr-$n.qcow2" "$images/clifr-$n-seed.iso"
	;;
*)
	sed -n '2,13p' "$0"
	exit 2
	;;
esac
