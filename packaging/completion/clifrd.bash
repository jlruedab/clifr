# bash completion for clifrd (packaging/completion/clifrd.bash)

_clifrd() {
	local cur=${COMP_WORDS[COMP_CWORD]} prev=${COMP_WORDS[COMP_CWORD-1]}
	local opts="--config -C --data-dir -D --log-level --version -v --interval
		--sys-interval --fd-interval --redact --proc-io --duration --cpu-budget
		--budget-window --verify-every --flush-interval --early-flush --flush-rows --flush-bytes --retention
		--events --fd-mode --fd-full-every --tcp --keyframe-interval --gc-heap-target --max-cmdline --max-files-per-process --memory-guard --event-budget-processes --event-budget-processes-max --event-budget-cmdline --event-budget-connections
		--max-size --metrics --metrics-tls-config --serve --serve-tls-config --serve-tokens --serve-tls-dir --bpf-stats --pprof-dir --test-ebpf --ebpf-force-perf
		--ebpf-classic-fork --ebpf-kprobes --proc-root"
	local bundle="--data-dir -D --last --since --until -o --output --split"
	COMPREPLY=()
	case $prev in
	--config | -C | --data-dir | -D | -o | --output | --pprof-dir | --proc-root | --serve-tokens | --serve-tls-dir | --metrics-tls-config | --serve-tls-config | --file)
		COMPREPLY=($(compgen -f -- "$cur"))
		return
		;;
	token)
		COMPREPLY=($(compgen -W "new list revoke" -- "$cur"))
		return
		;;
	--log-level)
		COMPREPLY=($(compgen -W "error warn info debug" -- "$cur"))
		return
		;;
	--metrics)
		COMPREPLY=($(compgen -W "127.0.0.1:9100 [::1]:9100" -- "$cur"))
		return
		;;
	--events)
		COMPREPLY=($(compgen -W "auto ebpf proc_connector none" -- "$cur"))
		return
		;;
	--tcp)
		COMPREPLY=($(compgen -W "auto ebpf sample" -- "$cur"))
		return
		;;
	--fd-mode)
		COMPREPLY=($(compgen -W "held all" -- "$cur"))
		return
		;;
	esac
	if [[ " ${COMP_WORDS[*]:1:COMP_CWORD-1} " == *" bundle "* ]]; then
		COMPREPLY=($(compgen -W "$bundle" -- "$cur"))
	elif [[ " ${COMP_WORDS[*]:1:COMP_CWORD-1} " == *" token "* ]]; then
		COMPREPLY=($(compgen -W "--file --comment" -- "$cur"))
	elif [[ " ${COMP_WORDS[*]:1:COMP_CWORD-1} " == *" seal-setup "* ]]; then
		COMPREPLY=($(compgen -W "--new --data-dir -D" -- "$cur"))
	elif [[ $cur == -* ]]; then
		COMPREPLY=($(compgen -W "$opts" -- "$cur"))
	elif ((COMP_CWORD == 1)); then
		COMPREPLY=($(compgen -W "doctor bundle token seal-setup" -- "$cur"))
	fi
}
complete -F _clifrd clifrd
