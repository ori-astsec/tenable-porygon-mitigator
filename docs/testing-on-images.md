# Trying a change on a clean image first

The flow simulates a change on a model, which says what the change should do to reachability. It can't say whether the patch
level, driver or application on a real machine will behave. Before a change reaches production, try it on a clean image of
what it runs on. Every plan lists these under `test_first`: which OS or firewall version, which targets, and which image.

This is guidance, and porygon doesn't run any of it.

## Images

| Runs on | Where to get a clean image |
|---|---|
| Windows Server, Windows client | [Microsoft Evaluation Center](https://www.microsoft.com/en-us/evalcenter/). Versions out of support, like Windows Server 2008 R2, aren't offered: clone your own |
| Ubuntu | [Ubuntu cloud images](https://cloud-images.ubuntu.com/) |
| CentOS Stream | [CentOS cloud images](https://cloud.centos.org/centos/9-stream/) |
| Debian | [Debian cloud images](https://cloud.debian.org/images/cloud/) |
| Palo Alto firewalls | [VM-Series trial](https://www.paloaltonetworks.com/vm-series-trial), 30 days, by request |

Match the version in `test_first` as closely as you can: a mitigation's effect can depend on the build.

## Building a small range

- [Ludus](https://docs.ludus.cloud/) describes a range in YAML and builds it on Proxmox, including Windows and Linux machines
  and isolated networks. It needs a good amount of RAM per range, so check its requirements first.
- [CyberRangeCZ](https://cyberrange.cz/), the successor to the KYPO platform, is an open-source cyber range built around
  training exercises. Check its documentation for how it handles your images.

## What to check

1. Build the targets in `test_first` on an isolated network, with the vulnerable version installed.
2. Apply the change from the plan's preview, by hand. Nothing in porygon runs it.
3. Run the allowed traffic listed under the plan's `impact` (`traffic_crossing`), and confirm it still works.
4. Confirm the service you protect still works, and watch for false positives on an IPS change for a while.
5. Use the plan's rollback, and confirm the machine is back as it was.

A test like this shows the change is safe to make. It doesn't show the exploit is stopped unless you also test that, in
isolation, with something you're authorized to run.
