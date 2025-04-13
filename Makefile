# Makefile

all: ring_buffer_attack_bpf ring_buffer_attack_no_bpf disable_falco

ring_buffer_attack_bpf: ring_buffer_attack_bpf.c
	gcc ring_buffer_attack_bpf.c -o ring_buffer_attack_bpf

ring_buffer_attack_no_bpf: ring_buffer_attack_no_bpf.c
	gcc ring_buffer_attack_no_bpf.c -o ring_buffer_attack_no_bpf

disable_falco: disable_falco.c
	gcc disable_falco.c -o disable_falco

clean:
	rm -f ring_buffer_attack_bpf ring_buffer_attack_no_bpf disable_falco
