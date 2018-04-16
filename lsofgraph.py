#!/usr/bin/env python3

import sys
import subprocess
from collections import defaultdict


template_graph = '''
digraph G {{
    graph [center=true, margin=0.2, nodesep=0.1, ranksep=0.3, rankdir=LR];
	node [shape=box, style="rounded,filled", width=0, height=0, fontname=Helvetica, fontsize=10];
	edge [fontname=Helvetica, fontsize=10];
{nodes}
{edges}
}}
'''

template_node = 'p{pid} [label="{label}", fillcolor={color}];'
template_edge = 'p{a} -> p{b} [label="{label}", penwidth={pw}, weight={weight}, color={color}, dir="{dir}"];'


def main():
    if not sys.stdin.isatty():
        lines = sys.stdin
    else:
        cmd = ['lsof', '-n', '-F']
        cmd.extend(sys.argv[1:])
        lines = subprocess.check_output(cmd).decode('utf8').splitlines()

    proc_info, file_info = parse_lsof(lines)

    # Filter out kernel threads from file_info.
    kernel_thread_pids = set(find_kernel_threads(file_info))
    file_info = {pid: val for pid, val in file_info.items() if pid not in kernel_thread_pids}

    # Find inter-process connections.
    unix, fifo, pipe, tcp, udp = find_links(file_info)

    res = generate_dot(proc_info, file_info, unix, fifo, pipe, tcp, udp)
    print(res)


def find_kernel_threads(file_info):
    for pid, fd_fields in file_info.items():
        for fd, fields in fd_fields.items():
            if fd == 'txt' and fields.get('t') == 'unknown':
                yield pid
                continue


def parse_lsof(line_iter):
    # Mapping of pid to process-related fields (i.e. c, u, g).
    proc_info = defaultdict(dict)

    # Mapping of pid to pid fds to pid fd fields (i.e. a, t, n).
    file_info = defaultdict(lambda: defaultdict(dict))

    for line in line_iter:
        field, value = line[0], line[1:]

        if value.isdigit():
            value = int(value)

        if field == 'p':
            current_pid = value
            fields = proc_info[current_pid]
            continue

        if field == 'f':
            fields = file_info[current_pid][value]
            continue

        fields[field] = value

    return proc_info, file_info


def find_links(file_info):
    unix = defaultdict(dict)
    fifo = defaultdict(dict)
    pipe = defaultdict(dict)
    tcp = defaultdict(dict)
    udp = defaultdict(dict)

    for pid, fd_fields in file_info.items():
        for fd, fields in fd_fields.items():
            fd_type = fields['t']

            if fd_type == 'unix':
                name = fields.get('i') or fields.get('d')
                unix[name][pid] = fields

            elif fd_type == 'FIFO':
                fifo[fields['i']][pid] = fields

            elif fd_type in ('IPv4', 'IPv6'):
                if not '->' in fields['n']:
                    continue
                name = sorted(fields['n'].split('->', 1))
                dest = tcp if fields['P'] == 'TCP' else udp
                dest[r'\n'.join(name)][pid] = fields

    return unix, fifo, pipe, tcp, udp


def generate_dot(proc_info, file_info, unix, fifo, pipe, tcp, udp):
    edges = []
    nodes = []

    for pid in file_info:
        tags = proc_info[pid]
        name = tags.get('n') or tags.get('c')
        color = 'grey70' if tags['R'] == 1 else 'white'

        label = r'{name}\n{pid} {login}'.format(name=name, pid=pid, login=tags['L'])
        node = template_node.format(pid=pid, label=label, color=color)
        nodes.append(node)

        pid_parent = tags.get('R')
        if pid_parent and pid_parent != 1:
            edge = template_edge.format(a=pid_parent, b=pid, label='', color='gray60', pw=2, weight=100, dir='none')
            edges.append(edge)

    conn_props = (
        (unix, {'desc': 'unix', 'color': 'purple'}),
        (fifo, {'desc': 'fifo', 'color': 'green'}),
        (tcp,  {'desc': 'tcp', 'color': 'red'}),
        (udp,  {'desc': 'udp', 'color': 'orange'}),
    )

    for fd_pids, props in conn_props:
        for fd_name, pids in fd_pids.items():
            if len(pids) == 2:
                src, dst = pids

                fd_type = pids[src]['a']
                if fd_type == 'w':
                    dir = 'forward'
                elif fd_type == 'r':
                    dir = 'backward'
                else:
                    dir = 'both'

                label = r'%s:\n%s' % (props['desc'], fd_name)

                edge = template_edge.format(a=src, b=dst, label=label, pw=1, weight=10, dir=dir, **props)
                edges.append(edge)

    nodes = '\n'.join('\t' + i for i in nodes)
    edges = '\n'.join('\t' + i for i in edges)

    return template_graph.format(nodes=nodes, edges=edges).strip()


if __name__ == '__main__':
    main()
