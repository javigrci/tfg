/**
 * Transforma la respuesta de `GET /tools/chain-graph` en columnas por nivel
 * topológico para `<ExecutionGraph>`. La lógica del grafo vive en el backend
 * (declaraciones consume/produce); aquí solo se da forma a la vista.
 */

export type ChainType = 'web_port' | 'technology' | 'path'

export interface ChainGraphResponse {
  nodes: { tool: string; consumes: ChainType[]; produces: ChainType[] }[]
  edges: { src: string; dst: string; type: ChainType }[]
  order: string[][]
  refeed: string[]
  notes: string[]
}

export interface ToolBox {
  tool: string
  produces: ChainType[]
  feeds: { to: string; type: ChainType }[]
}

export interface GraphColumn {
  level: number
  tools: ToolBox[]
}

export function toColumns(resp: ChainGraphResponse): GraphColumn[] {
  const producesOf = new Map(resp.nodes.map(n => [n.tool, n.produces]))
  return resp.order.map((tools, level) => ({
    level,
    tools: tools.map(tool => ({
      tool,
      produces: producesOf.get(tool) ?? [],
      feeds: resp.edges
        .filter(e => e.src === tool)
        .map(e => ({ to: e.dst, type: e.type })),
    })),
  }))
}
