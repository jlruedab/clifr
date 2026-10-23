# bash completion for clifr (packaging/completion/clifr.bash)

_clifr() {
	local cur=${COMP_WORDS[COMP_CWORD]} prev=${COMP_WORDS[COMP_CWORD-1]}
	local opts="-a --at -S --since -U --until -T --tz --summary --changes --samples
		-e --every -n --number -j --json -I --interactive --plain -D --data-dir --style
		-H --host --token --tls-ca -l --license --verbose -v --version -h --help"
	local cmds="ps top pstree lsof ss netstat vmstat mpstat iostat pidstat free uptime df mount findmnt date hostname uname dmesg systemctl systemd-cgls swapon lsmod lsblk lslocks ipcs sysctl containers last nstat ip
		events life oom mounts help info verify export diff"
	COMPREPLY=()
	case $prev in
	-D | --data-dir | --tls-ca | -l | --license)
		COMPREPLY=($(compgen -f -- "$cur"))
		return
		;;
	-a | --at | -S | --since | -U | --until | -T | --tz | -e | --every | -n | --number | -H | --host | --token)
		return
		;;
	--style)
		COMPREPLY=($(compgen -W "current rhel-8 rhel-9 ubuntu-22.04" -- "$cur"))
		return
		;;
	esac
	if [[ $cur == -* ]]; then
		COMPREPLY=($(compgen -W "$opts" -- "$cur"))
	else
		COMPREPLY=($(compgen -W "$cmds" -- "$cur"))
	fi
}
complete -F _clifr clifr
