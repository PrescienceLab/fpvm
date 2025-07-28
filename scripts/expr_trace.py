import struct

def reinterpret_int64_as_double(int_value):
    """
    Reinterprets the bits of a 64-bit integer as a double-precision float.

    Args:
        int_value (int): The 64-bit integer to reinterpret.

    Returns:
        float: The double-precision float with the same bit representation.
    """
    # Pack the 64-bit integer into its 8-byte binary representation
    # 'Q' represents an unsigned long long (64-bit integer)
    packed_bytes = struct.pack('Q', int_value)

    # Unpack the 8-byte binary representation as a double-precision float
    # 'd' represents a double-precision float
    reinterpreted_double = struct.unpack('d', packed_bytes)[0]

    return reinterpreted_double


class Node:
    def __init__(self, node_id, operation, value, inputs=[]):
        self.node_id = node_id
        self.operation = operation
        self.value = value
        self.inputs = inputs

    def __repr__(self):
        return f"Node({self.operation}, {self.value})"

    def display(self, depth):
        if depth == 0 or self.operation == 'constant':
            return f'{self.value}'

        args = ' '.join([inp.display(depth - 1) for inp in self.inputs])
        result = f'({self.operation} {args})'

        return result

# id (int) -> Node
nodes = {}
constants = {}

with open('expressions.trace') as f:
    for i, line in enumerate(f):

        parts = line.split()
        node_id = int(parts[0][1:])
        operation = parts[1]
        value = reinterpret_int64_as_double(int(parts[2][1:]))
        inputs = []

        for inp in parts[3:]:
            if inp.startswith('n'):
                n = nodes[int(inp[1:])]
                inputs.append(n)
            elif inp.startswith('c'):
                # constant double precision float encoded as the bits of a 64-bit integer
                constant_value = reinterpret_int64_as_double(int(inp[1:]))
                if constant_value not in constants:
                    n = Node(len(constants), 'constant', constant_value)
                    constants[constant_value] = n
                inputs.append(constants[constant_value])

        n = Node(node_id, operation, value, inputs)
        nodes[node_id] = n

# Now we have all nodes in the `nodes` dictionary
# lets do some basic analysis


inputs = []
outputs = []

variables = {} # name -> Node
names = {} # Node -> name

def bind(node, name):
    names[node] = name
    variables[name] = node

for node in nodes.values():
    if node.operation.startswith("input."):
        inputs.append(node)
    if node.operation.startswith("output."):
        outputs.append(node)

print(f'void compute(double inputs[{len(inputs)}], double outputs[{len(outputs)}]) {{')


# codegen the input extraction
print('  // bind inputs')
for i, inp in enumerate(inputs):
    name = f'input_{i}'
    bind(inp, name)
    print(f'  double {names[inp]} = inputs[{i}];')


# going from each output, codegen the computation as a recursive function
# over the graph, not re-evaluating nodes that have already been computed (bound)
def codegen(node):
    if node.operation == 'constant':
        return node.value

    # if the node has already been computed, return its name
    if node in names:
        return names[node]

    name = f'node_{node.node_id}'
    bind(node, name)

    arguments = []
    infix = None

    for inp in node.inputs:
        arguments.append(codegen(inp))

    if node.operation.startswith('output.'):
        return codegen(node.inputs[0])

    if node.operation == 'add':
        infix = '+'
    elif node.operation == 'sub':
        infix = '-'
    elif node.operation == 'mul':
        infix = '*'
    elif node.operation == 'div':
        infix = '/'

    if infix is None:
        function_name = node.operation;
        if function_name == "neg":
            function_name = "-"
        arg_string = ', '.join(map(str, arguments))
        print(f'  double {name} = {function_name}({arg_string});')
    else:
        if len(arguments) != 2:
            raise ValueError(f'Expected 2 arguments for {node.operation}, got {len(arguments)}')
        print(f'  double {name} = {arguments[0]} {infix} {arguments[1]};')



    return name
    

# assign outputs
for i, out in enumerate(outputs):
    print(f'  outputs[{i}] = {codegen(out.inputs[0])};')

print('}')

exit()


print('digraph {')
print('  rankdir=LR;')
print('  node [shape=box];')
for node in nodes.values():
    print(f'  n{node.node_id} [label="{node.operation} = {node.value}"];')
    for inp in node.inputs:
        pfx = 'n'
        if inp.operation == 'constant':
            pfx = 'c'
            print(f'  {pfx}{inp.node_id} [label="{inp.value:.6f}"];')
        print(f'  {pfx}{inp.node_id} -> n{node.node_id};')

print('}')
# find the longest chain of nodes
