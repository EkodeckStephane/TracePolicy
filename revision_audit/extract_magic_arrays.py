"""Restricted structural decoding of released DGL pickles, without importing DGL/Torch.

Only inert stand-ins and NumPy storage reconstruction are allowed. No arbitrary
pickle global is executed. The adapter must validate arrays against source counts.
"""
import collections
import io
import pickle
import struct
import numpy as np


class Inert:
    def __new__(cls, *args):
        obj = super().__new__(cls)
        obj.args = args
        return obj

    def __setstate__(self, state):
        self.state = state
        if isinstance(state, dict):
            self.__dict__.update(state)


def storage_bytes(data):
    stream = io.BytesIO(data)
    for _ in range(3):
        Restricted(stream).load()
    unpickler = Restricted(stream)
    identifiers = []
    def persistent(pid):
        identifiers.append(pid)
        return pid
    unpickler.persistent_load = persistent
    unpickler.load()
    Restricted(stream).load()  # sorted storage keys
    if len(identifiers) != 1:
        raise ValueError('Expected one tensor storage')
    pid = identifiers[0]
    count = struct.unpack('<q', stream.read(8))[0]
    dtype = {'LongStorage': '<i8', 'FloatStorage': '<f4', 'DoubleStorage': '<f8',
             'IntStorage': '<i4', 'ByteStorage': 'u1', 'BoolStorage': '?'}[pid[1].__name__]
    raw = stream.read()
    array = np.frombuffer(raw, dtype=dtype)
    if len(array) != count or count != pid[4]:
        raise ValueError('Tensor storage count mismatch')
    return array


def tensor(storage, offset, size, stride, *ignored):
    offset=int(offset)
    if offset < 0 or any(int(x)<0 for x in size) or any(int(x)<0 for x in stride):
        raise pickle.UnpicklingError('Unsupported negative tensor layout')
    maximum=offset+sum((int(n)-1)*int(s) for n,s in zip(size,stride) if n)
    if len(size)!=len(stride) or (all(size) and maximum>=len(storage)):
        raise pickle.UnpicklingError('Tensor layout exceeds storage')
    storage = storage[offset:]
    return np.lib.stride_tricks.as_strided(storage, shape=tuple(size),
           strides=tuple(int(x)*storage.itemsize for x in stride)).copy()


class Restricted(pickle.Unpickler):
    classes = {}
    def find_class(self, module, name):
        if module == 'builtins' and name == 'bytearray':
            return bytearray
        if module == 'builtins' and name == 'getattr':
            def inert_getattr(cls, attr):
                if isinstance(cls, type) and issubclass(cls, Inert) and cls.__name__ == 'Scheme' and attr == '_reconstruct_scheme':
                    return lambda *args: cls(*args)
                raise pickle.UnpicklingError('Unapproved getattr')
            return inert_getattr
        if module == 'collections' and name == 'OrderedDict':
            return collections.OrderedDict
        if module == 'torch.storage' and name == '_load_from_bytes':
            return storage_bytes
        if module == 'torch._utils' and name == '_rebuild_tensor_v2':
            return tensor
        if module == 'dgl._ffi.object' and name == '_new_object':
            return lambda cls: cls()
        if module.startswith('dgl.') or (module == 'torch' and name.endswith('Storage')):
            key = (module, name)
            if key not in self.classes:
                self.classes[key] = type(name, (Inert,), {})
            return self.classes[key]
        raise pickle.UnpicklingError('Unapproved global: '+module+'.'+name)


def decode(data):
    return Restricted(io.BytesIO(data)).load()


def graph_arrays(data):
    g = decode(data)
    source, destination = g._graph.state.state[2]
    nodes = g._node_frames[0]._columns['type'].storage
    edges = g._edge_frames[0]._columns['type'].storage
    if len(source) != len(destination) or len(source) != len(edges):
        raise ValueError('Graph edge count mismatch')
    if not (np.all(source >= 0) and np.all(destination >= 0) and
            np.all(source < len(nodes)) and np.all(destination < len(nodes))):
        raise ValueError('Graph endpoints out of range')
    if g._node_frames[0]._num_rows != len(nodes) or g._edge_frames[0]._num_rows != len(edges):
        raise ValueError('Frame count mismatch')
    node_attr = g._node_frames[0]._columns['attr'].storage
    edge_attr = g._edge_frames[0]._columns['attr'].storage
    if not np.array_equal(node_attr.argmax(axis=1), nodes) or not np.array_equal(edge_attr.argmax(axis=1), edges):
        raise ValueError('Type/one-hot alignment mismatch')
    return source, destination, nodes, edges


if __name__ == '__main__':
    import zipfile
    from pathlib import Path
    archive = zipfile.ZipFile(Path(__file__).with_name('magic_theia_graphs.zip'))
    graph = decode(archive.read('train0.pkl'))
    print(graph.__dict__.keys())
    print(graph._graph.__dict__)
    print('node frames', graph._node_frames)
    print('edge frames', graph._edge_frames)
