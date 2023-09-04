#include "translation_state.h"

int drop(struct xlation *state)
{
	state->stats->rx_errors++;
	state->stats->rx_dropped++;
	return -EINVAL;
}

int drop_icmp(struct xlation *state, enum icmp_errcode icmp, __u32 info)
{
	state->result.icmp = icmp;
	state->result.info = info;
	return drop(state);
}
