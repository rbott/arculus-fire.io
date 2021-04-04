# arculus-fire.io

Maintaining firewall rulesets on and between hundreds of servers can be a burden. This projects helps you to deploy any number of local or centralized firewalls from one single ruleset which describes all traffic flows in, out and inside of your network.

## Running code off this repository

After cloning this repository you need to install the required Python modules. We advise to use a Python VirtualEnv for this:

```shell

virtualenv --python /usr/bin/python3 ~/venv/firewall-generator
source ~/venv/firewall-generator/bin/activate

pip -r requirements.txt
```

