## BPF Map Attack

This repository demonstrates how to attack BPF maps and execute commands without detection by security solutions that rely on BPF maps for event delivery and configuration.
⚠️ Disclaimer: This project is intended solely for educational and research purposes.

The exploit requires the container (pod) to have at least the SYS_PTRACE capability.
(Note: Although SYS_PTRACE is needed, the exploit does not use the ptrace system call directly  instead, it uses pidfd_open, since ptrace is often heavily monitored)
Additionally, the container must share the host process namespace (e.g., hostPID: true).

## Article

https://www.deep-kondah.com/you-see-me-now-you-dont-bpf-map-attacks-via-privileged-file-descriptor-hijacking/

## Test Deployment
- Deploy any ring buffer collector in your Kubernetes cluster, for example:
  - e.g https://github.com/mouadk/ebpf-ringbuffer
  - or
  - Install Falco with: "helm install falco falcosecurity/falco -f values.yaml[values.yaml](falco%2Fvalues.yaml) --create-namespace --namespace falco --set driver.kind=modern_ebpf"
- Build the exploit image:
  - docker build . -t bpf-map-attack
- Deploy the pod:
  - kubectl apply -f k8s/pod.yaml
- Access the pod:
  - kubectl exec -it bpf-map-attack sh
- Run the exploit:
  - ./ring_buffer_attack_no_bpf $target_pid


    
