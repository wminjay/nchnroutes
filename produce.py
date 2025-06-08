#!/usr/bin/env python3
import argparse
import csv
import logging
from ipaddress import IPv4Network, IPv6Network
import math

parser = argparse.ArgumentParser(description='Generate non-China routes for BIRD.')
parser.add_argument('--exclude', metavar='CIDR', type=str, nargs='*',
                    help='IPv4 ranges to exclude in CIDR format')
parser.add_argument('--include', metavar='CIDR', type=str, nargs='*',
                    help='IPv4/IPv6 ranges to force include even if they are in reserved ranges (useful for DNS fake IPs)')
parser.add_argument('--force', action='store_true',
                    help='Force add --include ranges even if they are covered by existing routes')
parser.add_argument('--verbose', '-v', action='store_true',
                    help='Enable verbose output')
parser.add_argument('--next', default="wg0", metavar = "INTERFACE OR IP",
                    help='next hop for where non-China IP address, this is usually the tunnel interface')
parser.add_argument('--ipv4-list', choices=['apnic', 'ipip'], default=['apnic', 'ipip'], nargs='*',
                    help='IPv4 lists to use when subtracting China based IP, multiple lists can be used at the same time (default: apnic ipip)')

args = parser.parse_args()

# 配置日志级别
if args.verbose:
    logging.basicConfig(level=logging.DEBUG, format='%(levelname)s: %(message)s')
else:
    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

class Node:
    def __init__(self, cidr, parent=None):
        self.cidr = cidr
        self.child = []
        self.dead = False
        self.parent = parent

    def __repr__(self):
        return "<Node %s>" % self.cidr

def dump_tree(lst, ident=0):
    for n in lst:
        print("+" * ident + str(n))
        dump_tree(n.child, ident + 1)

def dump_bird(lst, f):
    for n in lst:
        if n.dead:
            continue

        if len(n.child) > 0:
            dump_bird(n.child, f)

        elif not n.dead:
            f.write('route %s via "%s";\n' % (n.cidr, args.next))

RESERVED = [
    IPv4Network('0.0.0.0/8'),
    IPv4Network('10.0.0.0/8'),
    IPv4Network('127.0.0.0/8'),
    IPv4Network('169.254.0.0/16'),
    IPv4Network('172.16.0.0/12'),
    IPv4Network('192.0.0.0/29'),
    IPv4Network('192.0.0.170/31'),
    IPv4Network('192.0.2.0/24'),
    IPv4Network('192.168.0.0/16'),
    IPv4Network('198.18.0.0/15'),
    IPv4Network('198.51.100.0/24'),
    IPv4Network('203.0.113.0/24'),
    IPv4Network('240.0.0.0/4'),
    IPv4Network('255.255.255.255/32'),
    IPv4Network('169.254.0.0/16'),
    IPv4Network('127.0.0.0/8'),
    IPv4Network('224.0.0.0/4'),
    IPv4Network('100.64.0.0/10'),
]
RESERVED_V6 = []
if args.exclude:
    for e in args.exclude:
        if ":" in e:
            RESERVED_V6.append(IPv6Network(e))

        else:
            RESERVED.append(IPv4Network(e))

IPV6_UNICAST = IPv6Network('2000::/3')

def subtract_cidr(sub_from, sub_by):
    for cidr_to_sub in sub_by:
        for n in sub_from:
            if n.cidr == cidr_to_sub:
                n.dead = True
                break

            if n.cidr.supernet_of(cidr_to_sub):
                if len(n.child) > 0:
                    subtract_cidr(n.child, sub_by)

                else:
                    n.child = [Node(b, n) for b in n.cidr.address_exclude(cidr_to_sub)]

                break

root = []
root_v6 = [Node(IPV6_UNICAST)]

with open("ipv4-address-space.csv", newline='') as f:
    f.readline() # skip the title

    reader = csv.reader(f, quoting=csv.QUOTE_MINIMAL)
    for cidr in reader:
        if cidr[5] == "ALLOCATED" or cidr[5] == "LEGACY":
            block = cidr[0]
            cidr = "%s.0.0.0%s" % (block[:3].lstrip("0"), block[-2:], )
            root.append(Node(IPv4Network(cidr)))

with open("delegated-apnic-latest") as f:
    for line in f:
        if 'apnic' in args.ipv4_list and "apnic|CN|ipv4|" in line:
            line = line.split("|")
            a = "%s/%d" % (line[3], 32 - math.log(int(line[4]), 2), )
            a = IPv4Network(a)
            subtract_cidr(root, (a,))

        elif "apnic|CN|ipv6|" in line:
            line = line.split("|")
            a = "%s/%s" % (line[3], line[4])
            a = IPv6Network(a)
            subtract_cidr(root_v6, (a,))

if 'ipip' in args.ipv4_list:
    with open("china_ip_list.txt") as f:
        for line in f:
            line = line.strip('\n')
            a = IPv4Network(line)
            subtract_cidr(root, (a,))

# get rid of reserved addresses
subtract_cidr(root, RESERVED)
# get rid of reserved addresses
subtract_cidr(root_v6, RESERVED_V6)

def debug_node_structure(node, include_cidr, depth=0):
    """调试函数：显示节点结构"""
    indent = "  " * depth
    if not node.dead:
        if node.cidr.supernet_of(IPv4Network(include_cidr)):
            logging.debug(f"{indent}Node {node.cidr} (covers {include_cidr}) - children: {len(node.child)}")
            if len(node.child) > 0:
                logging.debug(f"{indent}  This node has children, so it won't appear in final output")
                for child in node.child[:3]:  # 只显示前3个子节点
                    debug_node_structure(child, include_cidr, depth + 1)
                if len(node.child) > 3:
                    logging.debug(f"{indent}  ... and {len(node.child) - 3} more children")
            else:
                logging.debug(f"{indent}  This node will appear in final output")

# Add back the force-included ranges
if args.include:
    for include_cidr in args.include:
        if ":" in include_cidr:
            # IPv6 address
            network = IPv6Network(include_cidr)
            # Check if this network is already covered by existing routes
            already_covered = False
            covering_route = None
            if not args.force:
                for existing_node in root_v6:
                    if not existing_node.dead and existing_node.cidr.supernet_of(network):
                        already_covered = True
                        covering_route = existing_node.cidr
                        break
            
            if already_covered:
                logging.warning(f"{include_cidr} is already covered by existing route {covering_route}, skipping (use --force to override)")
            else:
                root_v6.append(Node(network))
                if args.force:
                    logging.info(f"Force adding: {include_cidr}")
        else:
            # IPv4 address
            network = IPv4Network(include_cidr)
            # Check if this network is already covered by existing routes
            already_covered = False
            covering_route = None
            if not args.force:
                for existing_node in root:
                    if not existing_node.dead and existing_node.cidr.supernet_of(network):
                        already_covered = True
                        covering_route = existing_node.cidr
                        if args.verbose:
                            logging.debug(f"Found covering route {covering_route} for {include_cidr}")
                            debug_node_structure(existing_node, include_cidr)
                        break
            
            if already_covered:
                logging.warning(f"{include_cidr} is already covered by existing route {covering_route}, skipping (use --force to override)")
            else:
                root.append(Node(network))
                if args.force:
                    logging.info(f"Force adding: {include_cidr}")

with open("routes4.conf", "w") as f:
    dump_bird(root, f)

with open("routes6.conf", "w") as f:
    dump_bird(root_v6, f)
