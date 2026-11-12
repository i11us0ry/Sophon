import MarkdownIt from 'markdown-it'

export const markdownRenderer = new MarkdownIt({
  html: false,
  linkify: true,
  breaks: true,
  typographer: false,
})
