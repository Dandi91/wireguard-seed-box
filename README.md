# WireGuard Seed Box

A guide to set up a torrent client on your local server to download and upload through the remote server.

1. WireGuard tunnel and peer port forwarding
2. Torrent ~~jail~~ separate network namespace
3. Systemd scripts
4. Torrent client configuration

## WireGuard tunnel and peer port forwarding

For the beginning of this part you may
follow [this great guide](https://www.digitalocean.com/community/tutorials/how-to-set-up-wireguard-on-ubuntu-20-04)
from DigitalOcean all the way, skipping the optional parts in step 7. We don't need to route all traffic or DNS requests
through the VPN tunnel just yet.

When everything is done, you should be able to ping both ends of the tunnel (`10.8.0.1` and `10.8.0.2`).

Now, let's optionally allow all outgoing traffic from the local server through the VPN tunnel. For this, we need to
modify the WG peer config (`/etc/wireguard/wg0.conf` on local server) as follows:

```ini
[Interface]
...
Table = off

[Peer]
...
AllowedIPs = 0.0.0.0/0
```

By default, WG automatically setups routes for all `AllowedIPs`. Adding `0.0.0.0/0` essentially means setting up
the WG connection as a default gateway for your local server. To control routing more precise, we add the
`Table = off` line, so that WG doesn't do any routing. This allows us to check the VPN tunnel setup without putting
all our traffic through it.

Now we can ping stuff either on local connection or through the tunnel, using the `-I` flag to specify the network
interface:

```shell
# local
ping 8.8.8.8
# tunnel
ping -I wg0 8.8.8.8
```

Also, you may want to check TCP connectivity using something like `curl`, it has the `--interface` flag as well.

As the final step, we need to set port forwarding to allow our torrent client to seed through the VPN. Unfortunately,
`ufw` cannot forward ports, so we have to do it manually. Add the following to remote server's `/etc/ufw/before.rules`:

```shell
# custom port-forwarding
*filter
-A FORWARD -i eth0 -o wg0 -p tcp --syn --dport 51413 -m conntrack --ctstate NEW -j ACCEPT
-A FORWARD -i eth0 -o wg0 -p udp --dport 51413 -j ACCEPT
-A FORWARD -i eth0 -o wg0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
COMMIT
*nat
-A PREROUTING -i eth0 -p tcp --dport 51413 -j DNAT --to-destination 10.8.0.2
-A PREROUTING -i eth0 -p udp --dport 51413 -j DNAT --to-destination 10.8.0.2
COMMIT
```

where `eth0` is remote server's upstream interface and `51413` is the torrent peer port that you want to use
(`51413` is default used
by [Transmission](https://github.com/transmission/transmission/blob/main/docs/Editing-Configuration-Files.md#peer-port),
but you can pick any random port).

These rules handle incoming TCP and UDP connections on port `51413`, routing them to `10.8.0.2` (our local server).
The outgoing part is already handled by forwarding and masquerading rules that we set up for our tunnel previously.

Don't forget to restart `ufw` to apply the rules:

```shell
sudo ufw disable
sudo ufw enable
```

Now you may check port availability using the `netcat` utility:

```shell
# TCP
netcat -l 51413
netcat <remote-ip> 51413
# UDP
netcat -ul 51413
netcat -u <remote-ip> 51413
```

You should be able to type text on either side and see it echo on the other.

## Separate network namespace

There are several ways you can restrict an application to a specific network interface, but I find this one the most
appealing. It is application-independent and available on any modern Linux kernel. In addition, it doesn't hurt my brain
when I think about it, compared to iptables shenanigans.

Long story short, network namespace allows us to have a separate network environment with its own interfaces and routs,
which can coexist with the regular network of the local server. Namespaced applications do not have access to the
regular network and vice versa.

In order to reach outside the namespace, we use a pair of virtual interfaces, one of which sits inside the namespace.
This allows us, for example, to expose RPC management port for our torrent client, so that we could access it from
the local network.

You can find the complete Bash script in `setup-torrent-jail` file. It is basically a compilation of
[this WireGuard tutorial](https://www.wireguard.com/netns/)
and [this SO answer](https://unix.stackexchange.com/a/211110). Variables at the beginning of the script are:

- `NS_NAME` is the network namespace name to use, defaults to `tun_ns`
- `UPSTREAM_IFACE` is the main network interface for the local server, defaults to `eth0`
- `UPSTREAM_NETWORK_IP_MASK` is the local network that is behind `UPSTREAM_IFACE` and needs to access the RPC port of
  the torrent client
- `RPC_PORT` is the TCP port number that torrent client exposes to control it, defaults to Transmission's `9091`
- `LOCAL_ACCESSED_IPS` is a list of IPs that you want to route locally, rather than through the VPN tunnel
- `TUNNEL_IFACE` is the WG tunnel interface, defaults to `wg0`
- `TUNNEL_IP_MASK` is the WG tunnel network address, that is used in the WG peer config as `Address` parameter
- `TUNNEL_PEER_MTU` is the WG tunnel MTU setting, defaults to `1420`
- `PAIR_INTERNAL_IFACE` and `PAIR_EXTERNAL_IFACE` are the names of the paired virtual interfaces (the INTERNAL sits
  inside the namespace), `vin` and `vout` by default
- `PAIR_INTERNAL_IP_MASK` and `PAIR_EXTERNAL_IP_MASK` are corresponding IPs for the paired interfaces, picked from
  `10.69.0.0/30` network by default

The things that you most likely want to adjust to your local setup (or at least check they are correct) are
`UPSTREAM_IFACE`, `UPSTREAM_NETWORK_IP_MASK`, `RPC_PORT`, and `LOCAL_ACCESSED_IPS`. I found it useful to add your ISP's
DNS servers to `LOCAL_ACCESSED_IPS`, because otherwise they would be routed through the tunnel. If you have your local
router as a (caching) DNS server, you don't need a separate IP here because it would be routed locally as a part of
`UPSTREAM_NETWORK_IP_MASK` addresses.

If you don't want any addresses to be routed locally, leave it as an empty list:

```shell
LOCAL_ACCESSED_IPS=()
```

Before running a script, we need to make some adjustments to the WireGuard peer config. 
First, disable and stop `wg-quick@wg0.service` on the local server, as the script configures the WG interface a bit
differently.
```shell
sudo systemctl stop wg-quick@wg0.service
sudo systemctl disable wg-quick@wg0.service
```
Then go to the WG peer config (`/etc/wireguard/wg0.conf`) and comment out `Address` and `Table` lines from the
`[Interface]` section. Because we are using `wg setconf` command and not `wg-quick`, we have only a subset of options
available in the config.

Now run the script as a `root` user and check whether the namespace is created:
```shell
sudo ip netns list
```
should print the name of the namespace (`tun_ns` by default).

You can check that the tunnel is running by executing things inside the namespace using 
`ip netns exec <namespace> <cmd> <args>`:
```shell
sudo ip netns exec tun_ns ping 10.8.0.1
```

Also check that the routing inside the namespace is correct:
```shell
sudo ip -n tun_ns route

# output
default dev wg0 scope link src 10.8.0.2 
10.8.0.0/24 dev wg0 proto kernel scope link src 10.8.0.2 
10.69.0.0/30 dev vin proto kernel scope link src 10.69.0.1
...
```

Finally, check that RPC port is accessible from other computers on your local network:
```shell
sudo ip netns exec tun_ns netcat -l 9091
```

## Systemd scripts

Here I will be using Transmission as a torrent client, but pretty much all of it would apply to any other torrent client
that allows remote control.

First we need to change when the torrent is allowed to start because we want to create the namespace before that. In
order to do this, we will create a systemd service file to start our jail and then add it as a dependency for 
the torrent service.

Move the `setup-torrent-jail` script with the correct variables from the previous part to `/etc/network/`. Then copy the
`torrent-jail.service` file from the repository to `/etc/systemd/system/`
```shell
sudo mv setup-torrent-jail /etc/network/setup-torrent-jail
sudo mv torrent-jail.service /etc/systemd/system/torrent-jail.service
```
Also, don't forget to allow our script to be executed
```shell
sudo chmod u+x /etc/network/setup-torrent-jail
```

Then run `sudo systemctl edit <name-of-your-torrent-service>`, which will create an override file 
`/etc/systemd/system/<name>.d/override.conf` and open it for editing. For example,
```shell
sudo systemctl edit transmission-daemon.service
```

There are two things that we need to override here. First, add our `torrent-jail.service` as a dependency:
```ini
[Unit]
Requires=torrent-jail.service
After=torrent-jail.service
```
Second, specify the network namespace that we would like to run the torrent client in (replace `tun_ns` if you called
it differently):
```ini
[Service]
NetworkNamespacePath=/run/netns/tun_ns
```
Complete `override.conf` can be found in the repository. More on systemd and overrides is
[here](https://wiki.archlinux.org/title/systemd#Drop-in_files).

Reload systemd with `sudo systemctl daemon-reload` to detect all changes. After this, you can enable your torrent client
to start automatically at boot by
```shell
sudo systemctl enable transmission-daemon.service
```

A quick note: the `torrent-jail.service` that we just added does not have a teardown script, but any changes it does 
are not persisted over reboot. If you had already run the `setup-torrent-jail` script before, you may either reboot now
or ignore the errors when the service starts.

Now if you start the torrent client, it should be put into its dedicated network namespace
```shell
sudo systemctl start transmission-daemon.service
```
You can check it with `ip netns pids <namespace>` command that lists all PIDs that are in the namespace
```shell
systemctl status transmission-daemon.service
# note the "Main PID" line in the output
sudo ip netns pids tun_ns
# should print the same PID
```

## Torrent client configuration

Now it is time to finally configure our torrent client. Again, here I will be using Transmission as an example, but I'm
sure most of the remotely-controlled clients have a way to set this up.

The full config description of the Transmission can be found 
[here](https://github.com/transmission/transmission/blob/main/docs/Editing-Configuration-Files.md). This guide covers 
only settings related to the networking part, the rest of the Transmission setup you can find online. 

Before changing any settings, you need to stop `transmission-daemon` or it would overwrite any changes you made. 
By default, settings are located in `/var/lib/transmission-daemon/info/settings.json`. We are interested in the 
following lines:
- `bind-address-ipv4` - set this to `10.8.0.2` (IP address of the `wg0` interface inside the namespace)
- `peer-port` - set this to whatever port number you've forwarded in the first part of this guide (`51413` by default)
- `peer-port-random-on-start` - set to `false` because we picked a single dedicated port for that
- `port-forwarding-enabled` - set to `false` as well because we already forwarded this port manually
- `rpc-bind-address` - set to `10.69.0.1` (IP address of the internal part of the virtual interface pair)
- `rpc-port` - set to whatever port number you've picked as `RPC_PORT` in the second part of this guide (`9091` by 
default)
- `rpc-whitelist` - list all addresses you would like to remote control the torrent from (for example, `192.168.0.*`)

Save it and restart the torrent client. If all done correctly, you should be able to connect to Transmission's web
interface via `http://<local-server-ip>:9091` and in the settings see that the listening port is detected as open.

With this, the setup is done! Test it with one more reboot to see if things start correctly, and you're good to go.

## Some words on performance
If you notice that your seeding speed is low, you may want to lower the WG tunnel MTU to something like 1384. 
[Here](https://gist.github.com/nitred/f16850ca48c48c79bf422e90ee5b9d95) is a small research on the matter.
You can change it with `TUNNEL_PEER_MTU` variable in the `setup-torrent-jail` script.