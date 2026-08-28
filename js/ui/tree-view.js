(function(global) {
  'use strict';

  function makeRow(node, onSelectNode, onToggleExpand) {
    const row = document.createElement("div");
    row.className = "trow";
    row._n = node;

    const tw = document.createElement("span");
    tw.className = "twisty" + (node.kids.length ? "" : " empty");
    tw.textContent = node.kids.length ? (node.open ? "-" : "+") : "|";

    const cls = document.createElement("span");
    cls.className = "tagcls " + (["U", "APP", "CTX", "PRV"][node.cls] || "U");
    cls.textContent = ["U", "A", "CTX", "P"][node.cls] || "?";

    const tn = document.createElement("span");
    tn.className = "tagname";
    tn.textContent = node.tagName;

    row.appendChild(tw);
    row.appendChild(cls);
    row.appendChild(tn);

    if (node.role) {
      const r = document.createElement("span");
      r.className = "role";
      r.textContent = node.role;
      row.appendChild(r);
    }

    const mt = document.createElement("span");
    mt.className = "meta";
    mt.textContent = "@" + node.start + " (" + (node.end - node.start) + " B)";
    row.appendChild(mt);

    if (node.preview) {
      const v = document.createElement("span");
      v.className = "val";
      v.textContent = node.preview;
      row.appendChild(v);
    }

    tw.addEventListener("click", ev => {
      ev.stopPropagation();
      if (!node.kids.length) return;
      node.open = !node.open;
      if (typeof onToggleExpand === 'function') onToggleExpand(node);
    });

    row.addEventListener("click", () => {
      if (typeof onSelectNode === 'function') onSelectNode(node, row);
    });

    return row;
  }

  function renderInto(host, node, onSelectNode, onToggleExpand, selectedNode) {
    if (!host || !node) return;
    const row = makeRow(node, onSelectNode, onToggleExpand);
    if (node === selectedNode) row.classList.add("sel");
    host.appendChild(row);
    if (node.open && node.kids.length) {
      const kc = document.createElement("div");
      kc.className = "kids";
      for (const c of node.kids) {
        renderInto(kc, c, onSelectNode, onToggleExpand, selectedNode);
      }
      host.appendChild(kc);
    }
  }

  function renderTree(host, rootNode, onSelectNode, onToggleExpand, selectedNode) {
    const el = typeof host === 'string' ? document.getElementById(host) : host;
    if (!el) return;
    el.textContent = "";
    if (rootNode) {
      renderInto(el, rootNode, onSelectNode, onToggleExpand, selectedNode);
    }
  }

  function selectByNode(node, rootNode, renderAllFn, onSelectNodeFn) {
    let n = node;
    let changed = false;
    while (n) {
      if (!n.open && n.kids.length) {
        n.open = true;
        changed = true;
      }
      n = n.parent;
    }
    if (changed && typeof renderAllFn === 'function') {
      renderAllFn();
    }
    const rows = [...document.querySelectorAll(".trow")];
    for (const r of rows) r.classList.remove("sel");
    const target = rows.find(r => r._n === node);
    if (target) {
      target.classList.add("sel");
      if (typeof onSelectNodeFn === 'function') {
        onSelectNodeFn(node, target);
      }
      target.scrollIntoView({ block: "nearest" });
    }
  }

  const treeViewModule = {
    makeRow,
    renderInto,
    renderTree,
    selectByNode
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = treeViewModule;
  }
  global.PKCS7TreeView = treeViewModule;
})(typeof window !== 'undefined' ? window : global);
