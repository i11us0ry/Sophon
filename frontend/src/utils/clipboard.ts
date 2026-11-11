/**
 * 复制文本：优先使用 Clipboard API，失败时回退到 execCommand。
 * 回退路径用于 HTTP、iframe、文档未聚焦等 Clipboard API 不可用的场景。
 */
export async function copyText(text: string): Promise<boolean> {
  try {
    if (typeof navigator !== 'undefined' && navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text)
      return true
    }
  } catch {
    // 继续尝试 execCommand 回退。
  }
  return copyTextFallback(text)
}

function copyTextFallback(text: string): boolean {
  if (typeof document === 'undefined') {
    return false
  }
  const textarea = document.createElement('textarea')
  textarea.value = text
  textarea.setAttribute('readonly', '')
  textarea.style.position = 'fixed'
  textarea.style.top = '-9999px'
  textarea.style.left = '-9999px'
  textarea.style.opacity = '0'
  textarea.style.pointerEvents = 'none'
  document.body.appendChild(textarea)
  const selection = document.getSelection()
  const previousRange = selection && selection.rangeCount > 0 ? selection.getRangeAt(0) : null
  let copied = false
  try {
    textarea.select()
    textarea.setSelectionRange(0, textarea.value.length)
    copied = document.execCommand('copy')
  } catch {
    copied = false
  } finally {
    textarea.remove()
    if (previousRange && selection) {
      selection.removeAllRanges()
      selection.addRange(previousRange)
    }
  }
  return copied
}
