# joolif

WIP. Inspired by https://gist.github.com/danderson/664bf95f372acf106982bcc29ff56b53.

See [`start.sh`](start.sh).

## TODO

Current SIIT test results:

```
	IPv6:
		Successes: 45
		Failures:  0
		Queued:    24
	IPv4:
		Successes: 42
		Failures:  0
		Queued:    15
```

("Queued"s are also failures.)

- The code that sets up the interface is a hackjob quickly adapted from [snull](https://github.com/martinezjavier/ldd3/blob/master/snull/snull.c).
	- If you have experience writing network device drivers, please feel free to turn it upside down.
- Tested/developed in Debian 11's 5.10.0-27-amd64 kernel. I don't know if it'll work in anything else.
