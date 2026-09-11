import { describe, it, expect } from 'vitest'
import { gradeColor, gradeLabel } from './posture'

describe('gradeColor', () => {
  it('A+ y A son verdes', () => {
    expect(gradeColor('A+')).toContain('green')
    expect(gradeColor('A')).toContain('green')
  })

  it('F es rojo', () => {
    expect(gradeColor('F')).toContain('red')
  })

  it('cada banda tiene un color distinto de las adyacentes', () => {
    const grades = ['A+', 'B', 'C', 'D', 'F']
    const colors = grades.map(gradeColor)
    expect(new Set(colors).size).toBe(grades.length)
  })

  it('A y A+ comparten color', () => {
    expect(gradeColor('A')).toBe(gradeColor('A+'))
  })
})

describe('gradeLabel', () => {
  it('incluye la nota y el indicador de cobertura', () => {
    expect(gradeLabel('B', 6, 14)).toBe('B (6/14)')
  })
})
