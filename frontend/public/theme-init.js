;(function () {
  try {
    var stored = localStorage.getItem('sophon.theme')
    var theme =
      stored === 'light' || stored === 'dark'
        ? stored
        : window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches
          ? 'light'
          : 'dark'
    document.documentElement.dataset.theme = theme
  } catch (error) {
    document.documentElement.dataset.theme = 'dark'
  }
})()
