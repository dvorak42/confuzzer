import networkx as nx
import matplotlib.pyplot as plt

def startGraph():
    plt.ion()

def drawGraph(data, final=False):
    ids = {'': 0}
    labels = {0: 'MAIN'}
    edge_labels = {}
    graph = []
    nextID = 1
    for _, path in data.iteritems():
        prevNode = ['ROOT', 'ROOT', '']
        indx = ''
        for n in path:
            if '%s-%s' % (indx, n[0]) not in ids:
                ids['%s-%s' % (indx, n[0])] = nextID
                labels[nextID] = n[0] + ':\n  ' + n[1]
                nextID += 1
            graph.append((ids[indx], ids['%s-%s' % (indx, n[0])]))
            edge_labels[graph[-1]] = str(prevNode[2])
            prevNode = n
            indx += '-' + n[0]

    G = nx.DiGraph()
    for edge in graph:
        G.add_edge(edge[0], edge[1])

    graph_pos=nx.graphviz_layout(G,prog='dot')
    plt.clf()
    nx.draw_networkx_nodes(G, graph_pos, node_size=1600, alpha=0.3, node_color='blue')
    nx.draw_networkx_edges(G, graph_pos, arrows=False)
    nx.draw_networkx_labels(G, graph_pos, labels, font_size=8)
    nx.draw_networkx_edge_labels(G, graph_pos, edge_labels)
    if final:
        plt.ioff()
        plt.show()
    else:
        plt.plot()
        plt.draw()


if __name__ == "__main__":
    data = {'': [('br_004010e0_1', 'RFLAGS_1 == 0', True), ('br_00401196_2', 'RFLAGS_2 != 0', False), ('br_004011bb_3', 'RFLAGS_2 == 0', False)], 'magic@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00': [('br_004010e0_1', 'RFLAGS_1 == 0', False), ('br_004010e0_2', 'RFLAGS_2 == 0', False), ('br_004010e0_3', 'RFLAGS_3 == 0', False), ('br_004010e0_4', 'RFLAGS_4 == 0', False), ('br_004010e0_5', 'RFLAGS_5 == 0', False), ('br_00401196_6', 'RFLAGS_6 != 0', False), ('br_004011bb_7', 'RFLAGS_6 == 0', False)], 'ma\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00': [('br_004010e0_1', 'RFLAGS_1 == 0', False), ('br_004010e0_2', 'RFLAGS_2 == 0', False), ('br_004010e0_3', 'RFLAGS_3 == 0', True), ('br_00401196_4', 'RFLAGS_4 != 0', False), ('br_004011bb_5', 'RFLAGS_4 == 0', False)], 'magi\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00': [('br_004010e0_1', 'RFLAGS_1 == 0', False), ('br_004010e0_2', 'RFLAGS_2 == 0', False), ('br_004010e0_3', 'RFLAGS_3 == 0', False), ('br_004010e0_4', 'RFLAGS_4 == 0', False), ('br_004010e0_5', 'RFLAGS_5 == 0', True), ('br_00401196_6', 'RFLAGS_6 != 0', False), ('br_004011bb_7', 'RFLAGS_6 == 0', False)], 'magic\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00': [('br_004010e0_1', 'RFLAGS_1 == 0', False), ('br_004010e0_2', 'RFLAGS_2 == 0', False), ('br_004010e0_3', 'RFLAGS_3 == 0', False), ('br_004010e0_4', 'RFLAGS_4 == 0', False), ('br_004010e0_5', 'RFLAGS_5 == 0', False), ('br_00401196_6', 'RFLAGS_6 != 0', True)], '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00': [('br_004010e0_1', 'RFLAGS_1 == 0', True), ('br_00401196_2', 'RFLAGS_2 != 0', False), ('br_004011bb_3', 'RFLAGS_2 == 0', False)], 'm\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00': [('br_004010e0_1', 'RFLAGS_1 == 0', False), ('br_004010e0_2', 'RFLAGS_2 == 0', True), ('br_00401196_3', 'RFLAGS_3 != 0', False), ('br_004011bb_4', 'RFLAGS_3 == 0', False)], 'mag\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00': [('br_004010e0_1', 'RFLAGS_1 == 0', False), ('br_004010e0_2', 'RFLAGS_2 == 0', False), ('br_004010e0_3', 'RFLAGS_3 == 0', False), ('br_004010e0_4', 'RFLAGS_4 == 0', True), ('br_00401196_5', 'RFLAGS_5 != 0', False), ('br_004011bb_6', 'RFLAGS_5 == 0', False)]}
    drawGraph(data)
