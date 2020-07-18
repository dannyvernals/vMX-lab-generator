"""Generate YML data config files used by Ansible for the generation of arbitrary lab topologies"""
# import pprint
# import time
import itertools
import ipaddress
import yaml


def load_config():
    """Load the base config"""
    with open('./start.yml') as base_config:
        config = yaml.load(base_config.read())
    return config


def parse_links(config_links):
    """Return a list of hosts and processed links ready to use for config generation.
    Links are given a unique global ID and unique local (i.e. per router) ID.
    These IDs are used as basis of the L2 topology and interface names."""
    int_links = [[i, 'internal'] for i in config_links['internal']]
    if CONFIG['ebgp']:
        ext_links = [[i, 'external'] for i in config_links['external']]
    else:
        ext_links = []
    links_list = ext_links + int_links
    links = []
    hosts = []
    link_id = 1
    local_ids = {}
    for link in links_list:
        end_points = []
        for host in link[0]:
            hosts.append(host)
            host_id = local_ids.setdefault(host, 0) + 1
            end_points.append((host, host_id))
            local_ids[host] = host_id
        link_dict = {'id': link_id,
                     'end_points': end_points,
                     'type': links_list[links_list.index(link)][1]
                     }
        links.append(link_dict)
        link_id = link_id + 1
    # deduping via set and reverting to list to sort
    hosts = list(set(hosts))
    hosts.sort()
    return hosts, links


def gen_link_config(link, ipv4_p2p_pool, ipv6_p2p_pool,
                    loc_ip_index, rem_ip_index, local_int, remote_int):
    """Create and return a dictionary of all the items needed for an interface's config"""
    loc_ipv6_index = loc_ip_index + 1
    rem_ipv6_index = rem_ip_index + 1
    lnk_id = link['id']
    # Using islice here as coercing the subnets generator objects to lists then using index wastes
    # loads of resources, particularly for the numerous IPv6 subnets.
    # However we must redefine the iterator on each pass otherwise we next() onto unintended slices
    # as networks are not necessarily generated sequentially.
    v4_iterator = ipaddress.ip_network(ipv4_p2p_pool).subnets(prefixlen_diff=7)
    link_network = next(itertools.islice(v4_iterator, lnk_id, lnk_id + 1))
    local_ip_addr = link_network[loc_ip_index]
    remote_ip_addr = link_network[rem_ip_index]
    if CONFIG['ipv6']:
        v6_iterator = ipaddress.ip_network(ipv6_p2p_pool).subnets(prefixlen_diff=16)
        link_network_v6 = next(itertools.islice(v6_iterator, lnk_id, lnk_id + 1))
        local_ipv6_addr = link_network_v6[loc_ipv6_index]
        remote_ipv6_addr = link_network_v6[rem_ipv6_index]
    else:
        local_ipv6_addr = ''
        remote_ipv6_addr = ''
    return {'local_int': local_int,
            'remote_int': remote_int,
            'remote_rtr': link['end_points'][rem_ip_index][0],
            'link_id': str(lnk_id),
            'type': link['type'],
            'local_ip': str(local_ip_addr) + '/31',
            'remote_ip': str(remote_ip_addr) + '/31',
            'local_ipv6': str(local_ipv6_addr) + '/64',
            'remote_ipv6': str(remote_ipv6_addr) + '/64'
            }


def gen_lsys_links(links, host, ipv4_p2p_pool, ipv6_p2p_pool):
    """
    Using the previously generated list of links:
    generate the link configuration suitable for use with a single MX with logical systems.
    A unique IP address is assigned for every interface based on the configured pool.
    """
    local_links = []
    for link in links:
        str_lnk_id = str(link['id'])
        if link['end_points'][0][0] == host:
            local_unit = str_lnk_id + '1'
            remote_unit = str_lnk_id + '2'
            local_int = 'lt-0/0/0.' + local_unit
            remote_int = 'lt-0/0/0.' + remote_unit
            link_config = gen_link_config(link, ipv4_p2p_pool, ipv6_p2p_pool,
                                          0, 1, local_int, remote_int
                                          )
            local_links.append(link_config)
        elif link['end_points'][1][0] == host:
            local_unit = str_lnk_id + '2'
            remote_unit = str_lnk_id + '1'
            local_int = 'lt-0/0/0.' + local_unit
            remote_int = 'lt-0/0/0.' + remote_unit
            link_config = gen_link_config(link, ipv4_p2p_pool, ipv6_p2p_pool,
                                          1, 0, local_int, remote_int
                                          )
            local_links.append(link_config)
    return local_links


def gen_vmx_links(links, host, ipv4_p2p_pool, ipv6_p2p_pool):
    """Using the previously generated list of links:
    generate links suitable for use with a local KML instances or remote VMMs.
    A unique IP address is assigned for every interface based on the configured pool."""
    local_links = []
    base_int = 'ge-0/0/'
    for link in links:
        if link['end_points'][0][0] == host:
            local_int = base_int + str(link['end_points'][0][1]) + '.0'
            remote_int = base_int + str(link['end_points'][1][1]) + '.0'
            link_config = gen_link_config(link, ipv4_p2p_pool, ipv6_p2p_pool,
                                          0, 1, local_int, remote_int)
            local_links.append(link_config)
        elif link['end_points'][1][0] == host:
            local_int = base_int + str(link['end_points'][1][1]) + '.0'
            remote_int = base_int + str(link['end_points'][0][1]) + '.0'
            link_config = gen_link_config(link, ipv4_p2p_pool, ipv6_p2p_pool,
                                          1, 0, local_int, remote_int)
            local_links.append(link_config)
    return local_links


def gen_links(links, host):
    """Call relevant link generation function based on lab type."""
    local_links = []
    ipv4_p2p_pool = CONFIG['ipv4_p2p_pool']
    ipv6_p2p_pool = CONFIG['ipv6_p2p_pool']
    if CONFIG['type'] == 'lsys':
        local_links = gen_lsys_links(links, host, ipv4_p2p_pool, ipv6_p2p_pool)
    elif CONFIG['type'] == 'vmm':
        local_links = gen_vmx_links(links, host, ipv4_p2p_pool, ipv6_p2p_pool)
    elif CONFIG['type'] == 'kvm':
        local_links = gen_vmx_links(links, host, ipv4_p2p_pool, ipv6_p2p_pool)
    else:
        print("invalid lab type: '{}'".format(CONFIG['type']))
        exit()
    return local_links


def gen_rsvp(host, routers):
    """Generate RSVP data"""
    lsp_end_points = []
    if CONFIG['ibgp']['type'] == 'full_mesh':
        lsp_routers = CONFIG['ibgp']['routers']
    elif CONFIG['ibgp']['type'] == 'rr':
        lsp_routers = CONFIG['ibgp']['rrs'] + CONFIG['ibgp']['rrc']
    else:
        lsp_routers = []
    for lsp_router in lsp_routers:
        if lsp_router != host:
            lsp_end_points.append({'router': lsp_router,
                                   'ip': routers[lsp_router]['ipv4_loopback'][:-3]
                                   })
    return lsp_end_points


def gen_ebgp(host, routers, peer_type):
    """Generate eBGP data"""
    ebgp_neighbours = []
    peer_ip = ''
    for neigh in CONFIG['ebgp']:
        if neigh['remote'] == host:
            for link in routers[neigh['remote']]['links']:
                if link['remote_rtr'] == neigh['local']:
                    peer_ip = link[peer_type].split('/')[0]
                    break
            peer_name = neigh['local']
            peer_as = CONFIG['local_as']
            ebgp_neighbours.append({'ip': peer_ip, 'router': peer_name, 'asn': peer_as})
        elif neigh['local'] == host:
            for link in routers[neigh['local']]['links']:
                if link['remote_rtr'] == neigh['remote']:
                    peer_ip = link[peer_type].split('/')[0]
                    break
            peer_name = neigh['remote']
            peer_as = neigh['remote_as']
            ebgp_neighbours.append({'ip': peer_ip, 'router': peer_name, 'asn': peer_as})
    return ebgp_neighbours


def gen_ibgp(host, routers, ip_type):
    """Generate iBGP data"""
    bgp_neighbours = []
    if CONFIG['ibgp']['type'] == 'full_mesh':
        if host in CONFIG['ibgp']['routers']:
            for neighbour in CONFIG['ibgp']['routers']:
                if neighbour != host:
                    bgp_neighbours.append({'router': neighbour,
                                           'ip': routers[neighbour][ip_type].split('/')[0],
                                           'type': 'full_mesh'
                                           })
    if CONFIG['ibgp']['type'] == 'rr':
        if host in CONFIG['ibgp']['rrs']:
            for neighbour in CONFIG['ibgp']['rrs']:
                if neighbour != host:
                    bgp_neighbours.append({'router': neighbour,
                                           'ip': routers[neighbour][ip_type].split('/')[0],
                                           'type': 'full_mesh'
                                           })
            for neighbour in CONFIG['ibgp']['rrc']:
                if neighbour != host:
                    bgp_neighbours.append({'router': neighbour,
                                           'ip': routers[neighbour][ip_type].split('/')[0],
                                           'type': 'rrc'
                                           })
        elif host in CONFIG['ibgp']['rrc']:
            for neighbour in CONFIG['ibgp']['rrs']:
                bgp_neighbours.append({'router': neighbour,
                                       'ip': routers[neighbour][ip_type].split('/')[0],
                                       'type': 'rrs'
                                       })
    return bgp_neighbours


def gen_local_as(host, ibgp):
    """Find the local AS.  Assume if ibgp isn't empty we should use value from config file.
    Otherwise find it from the ebgp definitions"""
    local_as = ''
    if ibgp:
        local_as = CONFIG['local_as']
    else:
        for neigh in CONFIG['ebgp']:
            if neigh['remote'] == host:
                local_as = neigh['remote_as']
                break
    return local_as


def ip_to_hex(ip):
    """Config dec formatted IPv4 address to hex"""
    hextets = []
    for i in ip.split('.'):
        hextets.append(hex(int(i)).split('x')[1].zfill(2))
    return ''.join(hextets[0:2]) + '.' + ''.join(hextets[2:4])


def gen_router_config(hosts, links):
    """
    Generate secondary YML for the lab topology.  This is used later by Ansible.
    Ansible uses this data in conjunction with J2 templates to produce the actual device config.
    """
    routers = {}
    ipv4_lo_config = CONFIG['ipv4_loopback_pool']
    ipv4_loopback_pool = list(ipaddress.ip_network(ipv4_lo_config).subnets(prefixlen_diff=8))
    ipv6_loopback_pool = CONFIG['ipv6_loopback_pool']
    host_id = 1
    # 1st loop over hosts: populate a dict with routers, their loopbacks and links:
    for host in hosts:
        routers.setdefault(host, {})
        routers[host]['host_id'] = host_id
        ipv4_loopback = str(ipv4_loopback_pool[host_id])
        routers[host]['ipv4_loopback'] = ipv4_loopback
        if CONFIG['ipv6']:
            ipv6_address = ipv6_loopback_pool.split('/')[0] + str(host_id) + '/128'
            routers[host]['ipv6_loopback'] = ipv6_address
        routers[host]['ipv4_hex_loopback'] = ip_to_hex(ipv4_loopback.split('/')[0])
        routers[host]['links'] = gen_links(links, host)
        host_id = host_id + 1
    # 2nd loop over hosts, needed as:
    # some functions key into the partially created routers dict to lookup neighbours (i.e. BGP).
    # Here we finish routers dict formation.
    for host in hosts:
        routers[host]['igp'] = CONFIG['igp']
        routers[host]['mpls'] = CONFIG['mpls']
        routers[host]['ibgp'] = gen_ibgp(host, routers, 'ipv4_loopback')
        if CONFIG['ebgp']:
            routers[host]['ebgp'] = gen_ebgp(host, routers, 'remote_ip')
        if CONFIG['ipv6']:
            routers[host]['ibgp_v6'] = gen_ibgp(host, routers, 'ipv6_loopback')
            if CONFIG['ebgp']:
                routers[host]['ebgp_v6'] = gen_ebgp(host, routers, 'remote_ipv6')
        routers[host]['local_as'] = gen_local_as(host, routers[host]['ibgp'])
        if routers[host]['mpls'] == 'rsvp':
            routers[host]['lsps'] = gen_rsvp(host, routers)
    return routers


def gen_host_vars():
    pass


def gen_man_net(man_net):
    """
    Generate the vars needed for a management network from the passed range.
    """
    man_net = ipaddress.ip_network(man_net)
    mask = str(man_net.netmask)
    ip_addr = str(list(man_net.hosts())[0])
    # Allocate top half of the management range for DHCP, leaving bottom half for static
    ip_addr_upper = list(list(man_net.subnets(prefixlen_diff=1))[1].hosts())
    range_st = str(ip_addr_upper[0])
    range_end = str(ip_addr_upper[-1])
    vnets_ips = {'fxp-net':
                 {'ip_addr': ip_addr,
                  'mask': mask,
                  'range_st': range_st,
                  'range_end': range_end
                  }
                 }
    return vnets_ips


def gen_multi_vmx(hosts, links):
    """
    Produce the YML to support Ansible instantiation of multiple KVM vMXs.
    Each vMX (vcp + vfp) is one router within the topology.
    Interconnection is provided via logical L2 on the host OS.
    (currently linux bridges, maybe add option for OVS later)
    """
    re_list = []
    pfe_list = []
    vnets_list = ['fxp-net']
    for link in links:
        vnets_list.append(
            (link['end_points'][0][0] + '-'
             + link['end_points'][1][0] + '-'
             + 'ext-net' + str(link['id'])
             )
        )
    console = int(CONFIG['vmx_resources']['console_port_start'])
    hst = 1
    for host in hosts:
        management_ip = str(list(ipaddress.ip_network(CONFIG['management_network']).hosts())[hst])
        re_list.append(
            {'name': host + '-vcp',
             'vnets': ['fxp-net', host + '-int-net'],
             'console': console,
             'management_ip': management_ip
             }
        )
        hst += 1
        vnets_list.append(host + '-int-net')
        console += 1
        local_nets = ['fxp-net', host + '-int-net']
        temp_nets = []
        for link in links:
            if host == link['end_points'][0][0]:
                temp_nets.append({'bridge': vnets_list[link['id']],
                                  'local_endpoint': link['end_points'][0][1]}
                                 )
            elif host == link['end_points'][1][0]:
                temp_nets.append({'bridge': vnets_list[link['id']],
                                  'local_endpoint': link['end_points'][1][1]}
                                 )
        temp_nets = sorted(temp_nets, key=lambda x: x['local_endpoint'])
        local_nets = local_nets + [x['bridge'] for x in temp_nets]
        pfe_list.append(
            {'name': host + '-vfp',
             'vnets': local_nets,
             'console': console
             }
        )
        console += 1
    kvm_out_dict = CONFIG['vmx_resources']
    kvm_out_dict['vnets'] = vnets_list
    kvm_out_dict['vnets_ips'] = gen_man_net(CONFIG['management_network'])
    kvm_out_dict['res'] = re_list
    kvm_out_dict['pfes'] = pfe_list
    kvm_out_dict['routers'] = hosts
    return kvm_out_dict


def gen_single_vmx():
    """
    Produce the YML to support Ansible instantiation of one KVM vMX.
    A multi-router topology is overlaid later with logical systems.
    """
    vnets = ['fxp-net', 'pri-ext-vnet', 'vmx1-int-net']
    kvm_out_dict = CONFIG['vmx_resources']
    kvm_out_dict['vnets'] = vnets
    kvm_out_dict['vnets_ips'] = gen_man_net(CONFIG['management_network'])
    kvm_out_dict['pfes'] = [
        {'name': 'vmx1-vfp',
         'vnets': ['fxp-net', 'vmx1-int-net', 'pri-ext-vnet'],
         'console': '8602'
         }
    ]
    kvm_out_dict['res'] = [
        {'name': 'vmx1-vcp',
         'vnets': ['fxp-net', 'vmx1-int-net'],
         'console': '8601',
         'management_ip': '172.12.1.2'
         }
    ]
    return kvm_out_dict


def gen_kvm_config(hosts, links):
    if CONFIG['type'] == 'kvm':
        output = gen_multi_vmx(hosts, links)
    elif CONFIG['type'] == 'lsys':
        output = gen_single_vmx()
    else:
        output = ''
    return output


def gen_hosts_file(kvm_out):
    """
    Generate the Ansible hosts file from the structured data we've already created for KVM
    image and network instantiation.
    """
    hosts_dict = {}
    for router in kvm_out['res']:
        print(router)
        name = router['name'][:-4]
        print(name)
        hosts_dict[name] = {'ansible_host': router['management_ip'],
                            'console': router['console']
                            }
    def_gw = kvm_out['vnets_ips']['fxp-net']['ip_addr']
    # TODO: set proper CIDR value
    group_dict = {'all_virts':
                      {'hosts': hosts_dict,
                       'vars': {'def_gw': def_gw, 'CIDR': 24}
                       }
                  }
    return group_dict


def main():
    """Main script body"""
    hosts, links = parse_links(CONFIG['links'])
    routers_out = gen_router_config(hosts, links)
    kvm_out = gen_kvm_config(hosts, links)
    hosts_out = gen_hosts_file(kvm_out)
    # with open('./yml_out/' + CONFIG['type'] + '_' +
    # time.strftime('%d-%m-%y', time.gmtime()) + '.conf', 'w') as fh:
    with open('./yml_out/' + 'routers.yml', 'w') as routers_out_file:
        routers_out_file.write(yaml.dump(routers_out))
    with open('./yml_out/' + 'kvm.yml', 'w') as kvm_out_file:
        kvm_out_file.write(yaml.dump(kvm_out))
    with open('./yml_out/' + 'vMX_hosts.yml', 'w') as hosts_out_file:
        hosts_out_file.write(yaml.dump(hosts_out))


if __name__ == '__main__':
    CONFIG = load_config()
    main()
