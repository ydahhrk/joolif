# joolif

**This repository is obsolete; the project is being moved to [Codeberg](https://codeberg.org/IPv6-Monostack/joolif-net-next).**

WIP. Inspired by https://gist.github.com/danderson/664bf95f372acf106982bcc29ff56b53.

See [`start.sh`](start.sh).

## TODO

Current SIIT test results:

```
	IPv6:
		Successes: 66
		Failures:  0
		Queued:    0
	IPv4:
		Successes: 56
		Failures:  0
		Queued:    0
```

("Queued"s are also failures.)

- The code that sets up the interface is a hackjob quickly adapted from [snull](https://github.com/martinezjavier/ldd3/blob/master/snull/snull.c).
	- If you have experience writing network device drivers, please feel free to turn it upside down.
- Needs general code cleanup, especially `icmp_send()`.
- Tested/developed in kernel 6.9.0-rc7-virtme. I don't know if it'll work in anything else.
