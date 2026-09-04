import { describe, expect, it } from 'vitest'
import { toColumns, type ChainGraphResponse } from './chainGraph'

const full: ChainGraphResponse = {
  nodes: [
    { tool: 'nmap', consumes: [], produces: ['web_port', 'technology'] },
    { tool: 'nikto', consumes: ['web_port', 'path'], produces: ['path'] },
    { tool: 'nuclei', consumes: ['web_port', 'technology', 'path'], produces: ['path'] },
  ],
  edges: [
    { src: 'nmap', dst: 'nikto', type: 'web_port' },
    { src: 'nmap', dst: 'nuclei', type: 'technology' },
    { src: 'nikto', dst: 'nuclei', type: 'path' },
  ],
  order: [['nmap'], ['nikto', 'nuclei']],
  refeed: ['nikto', 'nuclei'],
  notes: [],
}

describe('toColumns', () => {
  it('crea una columna por nivel topológico', () => {
    const cols = toColumns(full)
    expect(cols.map(c => c.tools.map(x => x.tool))).toEqual([['nmap'], ['nikto', 'nuclei']])
  })

  it('feeds por herramienta = aristas cuyo src es esa herramienta', () => {
    const cols = toColumns(full)
    const nmap = cols[0].tools[0]
    expect(nmap.feeds.map(f => `${f.to}:${f.type}`).sort()).toEqual(['nikto:web_port', 'nuclei:technology'])
    const nuclei = cols[1].tools.find(x => x.tool === 'nuclei')!
    expect(nuclei.feeds).toEqual([])
  })

  it('single_tool → una columna sin feeds', () => {
    const cols = toColumns({
      nodes: [{ tool: 'nmap', consumes: [], produces: ['web_port', 'technology'] }],
      edges: [], order: [['nmap']], refeed: [], notes: ['single_tool'],
    })
    expect(cols).toHaveLength(1)
    expect(cols[0].tools[0].feeds).toEqual([])
  })
})
