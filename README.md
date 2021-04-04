# arculus-fire.io

Maintaining firewall rulesets on and between hundreds of servers can be a burden. This projects helps you to deploy any number of local or centralized firewalls from one single ruleset which describes all traffic flows in, out and inside of your network.

## Running Code Off This Repository

After cloning this repository you need to install the required Python modules. We advise to use a Python VirtualEnv for this:

```shell

virtualenv --python /usr/bin/python3 ~/venv/firewall-generator
source ~/venv/firewall-generator/bin/activate

pip -r requirements.txt
```

## Current State

arculus-fire.io is in a very early state and has not seen any releases yet. The available output generators for `iptables` and `nftables` are in a proof-of-concept state and **must not** be used in production. Please check the [open issues](https://github.com/rbott/arculus-fire.io/issues) to see all currently known issues/todos. PRs are always welcome!

