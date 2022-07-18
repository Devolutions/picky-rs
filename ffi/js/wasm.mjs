let wasm;

const heap = new Array(32).fill(undefined);

heap.push(undefined, null, true, false);

function getObject(idx) { return heap[idx]; }

let heap_next = heap.length;

function dropObject(idx) {
    if (idx < 36) return;
    heap[idx] = heap_next;
    heap_next = idx;
}

function takeObject(idx) {
    const ret = getObject(idx);
    dropObject(idx);
    return ret;
}

function addHeapObject(obj) {
    if (heap_next === heap.length) heap.push(heap.length + 1);
    const idx = heap_next;
    heap_next = heap[idx];

    heap[idx] = obj;
    return idx;
}

const imports = {
  env: { },
  __wbindgen_placeholder__: {
    __wbindgen_object_drop_ref(arg0) {
      takeObject(arg0);
    },
    __wbg_process_2f24d6544ea7b200(arg0) {
        const ret = getObject(arg0).process;
        return addHeapObject(ret);
    },
    __wbindgen_is_object(arg0) {
      const val = getObject(arg0);
      const ret = typeof(val) === 'object' && val !== null;
      return ret;
    },
    __wbg_versions_6164651e75405d4a(arg0) {
      const ret = getObject(arg0).versions;
      return addHeapObject(ret);
    },
    __wbg_node_4b517d861cbcb3bc(arg0) {
      const ret = getObject(arg0).node;
      return addHeapObject(ret);
    },
    __wbindgen_is_string(arg0) {
      const ret = typeof(getObject(arg0)) === 'string';
      return ret;
    },

    __wbg_modulerequire_3440a4bcf44437db() { return handleError(function (arg0, arg1) {
        const ret = module.require(getStringFromWasm0(arg0, arg1));
        return addHeapObject(ret);
    }, arguments) },

    __wbg_crypto_98fc271021c7d2ad(arg0) {
        const ret = getObject(arg0).crypto;
        return addHeapObject(ret);
    },

    __wbg_msCrypto_a2cdb043d2bfe57f(arg0) {
        const ret = getObject(arg0).msCrypto;
        return addHeapObject(ret);
    },

  },
  __wbindgen_externref_xform__: {}
}

if (typeof fetch === 'undefined') {
  const fs = await import("fs");
  const path = await import("path");
  const url = await import("url");

  const wasmPath = path.resolve(path.join(path.dirname(url.fileURLToPath(import.meta.url)), "wasmpkg/picky.wasm"));
  const wasmFile = new Uint8Array(fs.readFileSync(wasmPath));
  const loadedWasm = await WebAssembly.instantiate(wasmFile, imports);
  wasm = loadedWasm.instance.exports;
} else {
  const loadedWasm = await WebAssembly.instantiateStreaming(fetch("./picky.wasm"), imports);
  wasm = loadedWasm.instance.exports;
}

wasm.diplomat_init();

export default wasm;
