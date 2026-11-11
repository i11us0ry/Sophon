<script setup lang="ts">
import { ref, watch } from 'vue'
import {
  Handle,
  Panel,
  Position,
  VueFlow,
  type Connection,
  type Edge as FlowEdge,
  type Node as FlowNode,
} from '@vue-flow/core'
import { Background, BackgroundVariant } from '@vue-flow/background'
import { Controls } from '@vue-flow/controls'
import { MiniMap } from '@vue-flow/minimap'
import '@vue-flow/core/dist/style.css'
import '@vue-flow/core/dist/theme-default.css'
import '@vue-flow/controls/dist/style.css'
import '@vue-flow/minimap/dist/style.css'

import { useI18n } from '../../i18n'

interface GraphNode {
  id: string
  projectId: string
  kind: string
  title: string
  detail: string
  status: string
  confidence: number
  severity: string
  assetId: string
  source: string
  posX: number
  posY: number
}

interface GraphEdge {
  id: string
  projectId: string
  srcId: string
  dstId: string
  rel: string
}

const props = defineProps<{
  nodes: GraphNode[]
  edges: GraphEdge[]
  assets: Array<{ id: string; name: string }>
}>()

const emit = defineEmits<{
  (event: 'node-click', node: GraphNode): void
  (event: 'node-dblclick', node: GraphNode): void
  (event: 'edge-click', edge: GraphEdge): void
  (event: 'connect', payload: { source: string; target: string }): void
  (event: 'layout-change', items: Array<{ id: string; x: number; y: number }>): void
}>()

const { t } = useI18n()

// 探索图设计：彩色图标方块 + 状态徽章 + 关系配色。
const KIND_META: Record<string, { labelKey: string; char: string; color: string }> = {
  begin: { labelKey: 'graph.kind.begin', char: '起', color: '#8b949e' },
  goal: { labelKey: 'graph.kind.goal', char: '目', color: '#3fb950' },
  intent: { labelKey: 'graph.kind.intent', char: '意', color: '#58a6ff' },
  fact: { labelKey: 'graph.kind.fact', char: '实', color: '#d29922' },
  finding: { labelKey: 'graph.kind.finding', char: '漏', color: '#f85149' },
  hint: { labelKey: 'graph.kind.hint', char: '示', color: '#a371f7' },
  asset: { labelKey: 'graph.kind.asset', char: '资', color: '#39c5cf' },
  chain: { labelKey: 'graph.kind.chain', char: '链', color: '#db61a2' },
  digest: { labelKey: 'graph.kind.digest', char: '折', color: '#6e7681' },
}

const REL_COLOR: Record<string, string> = {
  spawns: '#3fb950',
  derived_from: '#a371f7',
  yields: '#d29922',
  proves: '#f85149',
  blocks: '#da3633',
  contradicts: '#8957e5',
  digest: '#8b949e',
}

const STATE_TONE: Record<string, string> = {
  open: '#58a6ff',
  running: '#58a6ff',
  met: '#3fb950',
  done: '#3fb950',
  confirmed: '#3fb950',
  active: '#a371f7',
  blocked: '#d29922',
  exhausted: '#8b949e',
  capacity_blocked: '#db6d28',
  abandoned: '#8b949e',
  dismissed: '#8b949e',
  consumed: '#8b949e',
  cold: '#6e7681',
  candidate: '#58a6ff',
  testing: '#d29922',
  verified: '#3fb950',
  failed: '#f85149',
}

const flowNodes = ref<FlowNode[]>([])
const flowEdges = ref<FlowEdge[]>([])

function kindMeta(kind: string) {
  return KIND_META[kind] ?? KIND_META.intent
}

function isLive(node: GraphNode) {
  return node.kind === 'intent' && node.status === 'running'
}

function statusLabel(status: string) {
  const key = `graphStatus.${status}`
  const label = t(key)
  return label === key ? status : label
}

function stateTone(status: string) {
  return STATE_TONE[status] ?? '#8b949e'
}

function shortId(id: string) {
  return id.slice(0, 6)
}

function assetName(assetId: string) {
  if (!assetId) {
    return ''
  }
  return props.assets.find((item) => item.id === assetId)?.name ?? assetId
}

function pushMap(map: Map<string, string[]>, key: string, value: string) {
  const items = map.get(key)
  if (items) {
    items.push(value)
  } else {
    map.set(key, [value])
  }
}

const COL_W = 340
const ROW_H = 150

// 分层布局：DFS 断环 + 最长路径分层 + 4 轮 barycenter 排序。
function computeLayout(
  nodes: GraphNode[],
  edges: GraphEdge[],
): Map<string, { x: number; y: number }> {
  const order = nodes.map((node) => node.id)
  const idset = new Set(order)
  const valid = edges.filter((edge) => idset.has(edge.srcId) && idset.has(edge.dstId))
  const key = (src: string, dst: string) => `${src}->${dst}`

  const out = new Map<string, string[]>()
  for (const edge of valid) {
    pushMap(out, edge.srcId, edge.dstId)
  }

  const seen = new Map<string, 0 | 1 | 2>()
  const back = new Set<string>()
  for (const root of order) {
    if ((seen.get(root) ?? 0) !== 0) {
      continue
    }
    const stack: Array<{ id: string; index: number }> = [{ id: root, index: 0 }]
    seen.set(root, 1)
    while (stack.length) {
      const top = stack[stack.length - 1]
      const neighbors = out.get(top.id) ?? []
      if (top.index >= neighbors.length) {
        seen.set(top.id, 2)
        stack.pop()
        continue
      }
      const next = neighbors[top.index++]
      const state = seen.get(next) ?? 0
      if (state === 1) {
        back.add(key(top.id, next))
      } else if (state === 0) {
        seen.set(next, 1)
        stack.push({ id: next, index: 0 })
      }
    }
  }

  const dagSucc = new Map<string, string[]>()
  const indeg = new Map<string, number>(order.map((id) => [id, 0]))
  for (const edge of valid) {
    if (back.has(key(edge.srcId, edge.dstId))) {
      continue
    }
    pushMap(dagSucc, edge.srcId, edge.dstId)
    indeg.set(edge.dstId, (indeg.get(edge.dstId) ?? 0) + 1)
  }

  const layer = new Map<string, number>(order.map((id) => [id, 0]))
  const queue = order.filter((id) => (indeg.get(id) ?? 0) === 0)
  for (let index = 0; index < queue.length; index++) {
    const current = queue[index]
    for (const next of dagSucc.get(current) ?? []) {
      layer.set(next, Math.max(layer.get(next) ?? 0, (layer.get(current) ?? 0) + 1))
      const remaining = (indeg.get(next) ?? 0) - 1
      indeg.set(next, remaining)
      if (remaining === 0) {
        queue.push(next)
      }
    }
  }

  const maxLayer = Math.max(0, ...layer.values())
  let columns: string[][] = Array.from({ length: maxLayer + 1 }, () => [])
  for (const id of order) {
    columns[layer.get(id) ?? 0].push(id)
  }

  const columnIndex = new Map<string, number>()
  columns.forEach((ids, index) => ids.forEach((id) => columnIndex.set(id, index)))
  const neighbors = new Map<string, string[]>()
  for (const edge of valid) {
    const srcColumn = columnIndex.get(edge.srcId)
    const dstColumn = columnIndex.get(edge.dstId)
    if (
      srcColumn === undefined ||
      dstColumn === undefined ||
      Math.abs(srcColumn - dstColumn) !== 1
    ) {
      continue
    }
    pushMap(neighbors, edge.srcId, edge.dstId)
    pushMap(neighbors, edge.dstId, edge.srcId)
  }

  const sweep = (direction: 1 | -1) => {
    const start = direction === 1 ? 1 : columns.length - 2
    const end = direction === 1 ? columns.length : -1
    for (let column = start; column !== end; column += direction) {
      const reference = column - direction
      const referenceIndex = new Map(columns[reference].map((id, index) => [id, index]))
      const scored = columns[column].map((id, index) => {
        const positions = (neighbors.get(id) ?? [])
          .map((neighbor) => referenceIndex.get(neighbor))
          .filter((value): value is number => value !== undefined)
        const barycenter = positions.length
          ? positions.reduce((sum, value) => sum + value, 0) / positions.length
          : index
        return { id, barycenter, index }
      })
      scored.sort((a, b) => a.barycenter - b.barycenter || a.index - b.index)
      columns[column] = scored.map((item) => item.id)
    }
  }
  for (let iteration = 0; iteration < 4; iteration++) {
    sweep(1)
    sweep(-1)
  }

  const maxCount = Math.max(1, ...columns.map((column) => column.length))
  const midline = ((maxCount - 1) * ROW_H) / 2
  const positions = new Map<string, { x: number; y: number }>()
  columns.forEach((ids, column) => {
    const startY = midline - ((ids.length - 1) * ROW_H) / 2
    ids.forEach((id, index) => {
      positions.set(id, { x: column * COL_W, y: startY + index * ROW_H })
    })
  })
  return positions
}

function syncFlowGraph() {
  const layout = computeLayout(props.nodes, props.edges)
  const liveIds = new Set(props.nodes.filter(isLive).map((node) => node.id))

  flowNodes.value = props.nodes.map((node) => {
    const hasPosition = node.posX !== 0 || node.posY !== 0
    return {
      id: node.id,
      type: 'explore',
      position: hasPosition
        ? { x: node.posX, y: node.posY }
        : layout.get(node.id) ?? { x: 0, y: 0 },
      data: { node },
      sourcePosition: Position.Right,
      targetPosition: Position.Left,
    }
  })

  flowEdges.value = props.edges.map((edge) => {
    const color = REL_COLOR[edge.rel] ?? '#8b949e'
    const animated = liveIds.has(edge.dstId)
    return {
      id: edge.id,
      source: edge.srcId,
      target: edge.dstId,
      label: t(`graph.rel.${edge.rel}`),
      type: 'default',
      animated,
      labelShowBg: false,
      labelStyle: { fontSize: '10px', fontWeight: 600, fill: color },
      style: {
        stroke: color,
        strokeWidth: 2,
        strokeOpacity: animated ? 0.9 : 0.55,
      },
      markerEnd: { type: 'arrowclosed', color, width: 14, height: 14 },
    } as FlowEdge
  })
}

watch(() => [props.nodes, props.edges], syncFlowGraph, { deep: true, immediate: true })

function onNodeDragStop(event: { node: FlowNode }) {
  const position = event.node?.position
  if (!position) {
    return
  }
  emit('layout-change', [
    { id: event.node.id, x: Math.round(position.x), y: Math.round(position.y) },
  ])
}

function onNodeClick(event: { node: FlowNode }) {
  const node = props.nodes.find((item) => item.id === event.node.id)
  if (node) {
    emit('node-click', node)
  }
}

function onNodeDblClick(event: { node: FlowNode }) {
  const node = props.nodes.find((item) => item.id === event.node.id)
  if (node) {
    emit('node-dblclick', node)
  }
}

function onEdgeClick(event: { edge: FlowEdge }) {
  const edge = props.edges.find((item) => item.id === event.edge.id)
  if (edge) {
    emit('edge-click', edge)
  }
}

function onConnect(connection: Connection) {
  if (!connection.source || !connection.target || connection.source === connection.target) {
    return
  }
  const source = props.nodes.find((item) => item.id === connection.source)
  const target = props.nodes.find((item) => item.id === connection.target)
  if (source?.source === 'synthetic' || target?.source === 'synthetic') {
    return
  }
  emit('connect', { source: connection.source, target: connection.target })
}

function minimapNodeColor(node: FlowNode) {
  const data = node.data as { node?: GraphNode } | undefined
  return kindMeta(data?.node?.kind ?? 'intent').color
}
</script>

<template>
  <div class="graph-canvas">
    <VueFlow
      v-model:nodes="flowNodes"
      v-model:edges="flowEdges"
      :fit-view-on-init="true"
      :fit-view-options="{ padding: 0.2 }"
      :min-zoom="0.1"
      :max-zoom="2"
      :only-render-visible-elements="true"
      @node-drag-stop="onNodeDragStop"
      @node-click="onNodeClick"
      @node-double-click="onNodeDblClick"
      @edge-click="onEdgeClick"
      @connect="onConnect"
    >
      <Background :variant="BackgroundVariant.Dots" :gap="16" :size="1" />
      <Controls :show-interactive="false" />
      <MiniMap
        pannable
        zoomable
        :node-color="minimapNodeColor"
        :node-stroke-width="0"
        :node-border-radius="4"
        mask-color="rgb(148 163 184 / 0.18)"
      />
      <Panel position="top-left">
        <div class="graph-legend">
          <div class="graph-legend-row">
            <span v-for="(meta, kind) in KIND_META" :key="kind" class="graph-legend-item">
              <span class="graph-legend-icon" :style="{ background: meta.color }">{{ meta.char }}</span>
              {{ t(meta.labelKey) }}
            </span>
          </div>
          <div class="graph-legend-row graph-legend-relations">
            <span v-for="(color, rel) in REL_COLOR" :key="rel" class="graph-legend-item">
              <span class="graph-legend-line" :style="{ background: color }"></span>
              {{ t(`graph.rel.${rel}`) }}
            </span>
          </div>
        </div>
      </Panel>

      <template #node-explore="nodeProps">
        <div class="gnode" :class="{ selected: nodeProps.selected }">
          <Handle type="target" :position="Position.Left" class="gnode-handle" />
          <div
            class="gnode-card"
            :class="{
              live: isLive(nodeProps.data.node),
              digest: nodeProps.data.node.kind === 'digest',
              chain: nodeProps.data.node.kind === 'chain',
            }"
          >
            <div class="gnode-head">
              <span
                class="gnode-icon"
                :style="{ background: kindMeta(nodeProps.data.node.kind).color }"
              >
                {{ kindMeta(nodeProps.data.node.kind).char }}
              </span>
              <span class="gnode-kind">{{ t(kindMeta(nodeProps.data.node.kind).labelKey) }}</span>
              <span v-if="isLive(nodeProps.data.node)" class="gnode-pulse"></span>
            </div>
            <div class="gnode-title">{{ nodeProps.data.node.title }}</div>
            <div v-if="nodeProps.data.node.detail" class="gnode-detail">
              {{ nodeProps.data.node.detail }}
            </div>
            <div
              v-if="
                nodeProps.data.node.severity ||
                nodeProps.data.node.kind === 'fact' ||
                nodeProps.data.node.kind === 'hint' ||
                nodeProps.data.node.assetId
              "
              class="gnode-tags"
            >
              <span
                v-if="nodeProps.data.node.severity"
                class="gnode-tag"
                :style="{ color: kindMeta('finding').color }"
              >
                {{ t(`severity.${nodeProps.data.node.severity}`) }}
              </span>
              <span
                v-if="nodeProps.data.node.kind === 'fact' || nodeProps.data.node.kind === 'hint'"
                class="gnode-tag"
              >
                {{ t('graph.confidenceShort', { value: nodeProps.data.node.confidence }) }}
              </span>
              <span v-if="nodeProps.data.node.assetId" class="gnode-tag">
                {{ assetName(nodeProps.data.node.assetId) }}
              </span>
            </div>
            <div class="gnode-foot">
              <span class="gnode-state">
                <span
                  class="gnode-state-dot"
                  :style="{ background: stateTone(nodeProps.data.node.status) }"
                ></span>
                {{ statusLabel(nodeProps.data.node.status) }}
              </span>
              <span class="gnode-id">#{{ shortId(nodeProps.data.node.id) }}</span>
            </div>
          </div>
          <Handle type="source" :position="Position.Right" class="gnode-handle" />
        </div>
      </template>
    </VueFlow>
  </div>
</template>

<style scoped>
.graph-canvas {
  height: 560px;
  overflow: hidden;
  border: 1px solid var(--line);
  border-radius: var(--radius);
  background: var(--surface-soft);
  box-shadow: none;
}

.graph-canvas :deep(.vue-flow) {
  background: transparent;
}

.graph-canvas :deep(.vue-flow__node) {
  background: transparent;
  border: none;
  padding: 0;
  width: auto;
}

.graph-canvas :deep(.vue-flow__edge-text) {
  font-size: 10px;
  font-weight: 600;
}

.graph-canvas :deep(.vue-flow__controls) {
  overflow: hidden;
  border: 1px solid var(--line);
  border-radius: var(--radius);
  box-shadow: none;
}

.graph-canvas :deep(.vue-flow__controls-button) {
  background: var(--surface);
  border-bottom: 1px solid var(--border);
  fill: var(--text-secondary);
}

.graph-canvas :deep(.vue-flow__controls-button:hover) {
  background: var(--surface-soft);
}

.graph-canvas :deep(.vue-flow__minimap) {
  overflow: hidden;
  border: 1px solid var(--line);
  border-radius: var(--radius);
  background: var(--surface);
}

.gnode {
  width: 240px;
}

.gnode-card {
  position: relative;
  display: grid;
  gap: 6px;
  padding: 10px 12px 8px;
  border: 1px solid var(--line);
  border-radius: var(--radius);
  background: var(--surface);
  box-shadow: none;
  transition:
    border-color 0.15s ease,
    box-shadow 0.15s ease,
    transform 0.15s ease;
}

.gnode:hover .gnode-card {
  border-color: var(--accent);
  box-shadow: none;
  transform: translate(-1px, -1px);
}

.gnode.selected .gnode-card {
  border-color: var(--accent);
  box-shadow:
    inset 0 0 0 1px var(--accent),
    4px 4px 0 var(--block-shadow);
}

.gnode-card.live {
  border-color: var(--accent-line);
}

.gnode-card.digest {
  border-style: dashed;
}

.gnode-card.chain {
  border-color: var(--accent-coral);
}

.gnode-head {
  display: flex;
  gap: 8px;
  align-items: center;
}

.gnode-icon {
  display: grid;
  flex-shrink: 0;
  width: 24px;
  height: 24px;
  place-items: center;
  border-radius: var(--radius);
  color: #fff;
  font-size: 12px;
  font-weight: 700;
}

.gnode-kind {
  flex: 1;
  overflow: hidden;
  color: var(--text-secondary);
  font-size: 13px;
  font-weight: 600;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.gnode-pulse {
  position: relative;
  width: 8px;
  height: 8px;
  flex-shrink: 0;
  border: 1px solid var(--line);
  border-radius: 50%;
  background: var(--accent);
  animation: gnode-ping 1.4s ease-out infinite;
}

@keyframes gnode-ping {
  70% {
    box-shadow: 0 0 0 8px color-mix(in srgb, var(--accent) 0%, transparent);
  }

  100% {
    box-shadow: 0 0 0 0 transparent;
  }
}

.gnode-title {
  display: -webkit-box;
  overflow: hidden;
  color: var(--text-primary, var(--text-secondary));
  font-size: 13px;
  font-weight: 600;
  line-height: 1.35;
  overflow-wrap: anywhere;
  -webkit-box-orient: vertical;
  -webkit-line-clamp: 2;
}

.gnode-detail {
  display: -webkit-box;
  overflow: hidden;
  margin: 0;
  color: var(--text-muted);
  font-size: 11px;
  line-height: 1.4;
  overflow-wrap: anywhere;
  -webkit-box-orient: vertical;
  -webkit-line-clamp: 2;
}

.gnode-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
}

.gnode-tag {
  max-width: 140px;
  overflow: hidden;
  padding: 1px 6px;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  background: var(--surface-soft);
  color: var(--text-muted);
  font-size: 10px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.gnode-foot {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  margin-top: 2px;
}

.gnode-state {
  display: inline-flex;
  gap: 5px;
  align-items: center;
  color: var(--text-secondary);
  font-size: 10px;
  font-weight: 600;
}

.gnode-state-dot {
  width: 6px;
  height: 6px;
  border: 1px solid var(--line);
  border-radius: 50%;
}

.gnode-id {
  color: var(--text-muted);
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 10px;
}

.gnode :deep(.gnode-handle) {
  width: 8px;
  height: 8px;
  border: 2px solid var(--border-strong);
  background: var(--surface);
  opacity: 0;
  transition: opacity 0.15s ease;
}

.gnode:hover :deep(.gnode-handle),
.gnode.selected :deep(.gnode-handle) {
  opacity: 1;
}

.graph-legend {
  display: flex;
  flex-direction: column;
  gap: 8px;
  padding: 8px 10px;
  border: 1px solid var(--line);
  border-radius: var(--radius);
  background: color-mix(in srgb, var(--surface) 92%, transparent);
  font-size: 11px;
  box-shadow: none;
}

.graph-legend-row {
  display: flex;
  flex-wrap: wrap;
  gap: 6px 12px;
}

.graph-legend-relations {
  padding-top: 6px;
  border-top: 1px solid var(--border);
}

.graph-legend-item {
  display: inline-flex;
  gap: 5px;
  align-items: center;
  color: var(--text-secondary);
}

.graph-legend-icon {
  display: grid;
  width: 16px;
  height: 16px;
  place-items: center;
  border-radius: var(--radius);
  color: #fff;
  font-size: 10px;
  font-weight: 700;
}

.graph-legend-line {
  width: 16px;
  height: 2px;
  border-radius: var(--radius);
}
</style>
