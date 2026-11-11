// 登录页背景运行时：Canvas 粒子、鼠标视差、噪点轮换与生命周期管理。
export interface LoginSceneOptions {
  scene: HTMLElement
  canvas: HTMLCanvasElement
  noise: HTMLElement
}

interface Particle {
  x: number
  y: number
  radius: number
  speed: number
  drift: number
  alpha: number
  phase: number
  sprite: HTMLCanvasElement
}

const PARTICLE_COLORS = ['94, 234, 212', '244, 197, 66', '226, 232, 240']
const MAX_DPR = 1.5
const MAX_PARTICLES = 120
const MIN_PARTICLES = 32
const NOISE_INTERVAL_MS = 850

export function startLoginScene({ scene, canvas, noise }: LoginSceneOptions): () => void {
  const ctx = canvas.getContext('2d')
  if (!ctx) {
    return () => {}
  }

  const root = document.documentElement
  const reduceQuery = window.matchMedia('(prefers-reduced-motion: reduce)')
  const finePointer = window.matchMedia('(hover: hover) and (pointer: fine)')
  const dpr = Math.min(window.devicePixelRatio || 1, MAX_DPR)
  const sprites: HTMLCanvasElement[] = []
  const particles: Particle[] = []
  const noiseTiles: string[] = []
  const parallax = { tx: 0, ty: 0, x: 0, y: 0, active: false }

  let reduced = reduceQuery.matches
  let alphaScale = root.dataset.theme === 'light' ? 0.62 : 1
  let viewWidth = 0
  let viewHeight = 0
  let running = false
  let rafId = 0
  let lastTime = 0
  let noiseTimer = 0
  let noiseIndex = 0
  let resizeTimer = 0

  /* 粒子精灵：预渲染发光贴图，避免逐帧 shadowBlur 开销 */
  function buildSprites() {
    PARTICLE_COLORS.forEach((rgb) => {
      const sprite = document.createElement('canvas')
      const size = 64
      sprite.width = size
      sprite.height = size
      const sctx = sprite.getContext('2d')
      if (!sctx) {
        return
      }
      const gradient = sctx.createRadialGradient(size / 2, size / 2, 0, size / 2, size / 2, size / 2)
      gradient.addColorStop(0, `rgba(${rgb}, 0.95)`)
      gradient.addColorStop(0.28, `rgba(${rgb}, 0.45)`)
      gradient.addColorStop(1, `rgba(${rgb}, 0)`)
      sctx.fillStyle = gradient
      sctx.fillRect(0, 0, size, size)
      sprites.push(sprite)
    })
  }

  function spawnParticle(anywhere: boolean): Particle {
    return {
      x: Math.random() * viewWidth,
      y: anywhere ? Math.random() * viewHeight : viewHeight + Math.random() * 60,
      radius: 5 + Math.random() * 16,
      speed: 9 + Math.random() * 22,
      drift: (Math.random() - 0.5) * 9,
      alpha: 0.16 + Math.random() * 0.34,
      phase: Math.random() * Math.PI * 2,
      sprite: sprites[Math.floor(Math.random() * sprites.length)],
    }
  }

  function resizeParticles() {
    viewWidth = window.innerWidth
    viewHeight = window.innerHeight
    canvas.width = Math.round(viewWidth * dpr)
    canvas.height = Math.round(viewHeight * dpr)
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0)

    const budget = reduced ? 42000 : 26000
    const max = reduced ? 48 : MAX_PARTICLES
    const target = Math.round(Math.min(max, Math.max(MIN_PARTICLES, (viewWidth * viewHeight) / budget)))
    particles.length = 0
    for (let index = 0; index < target; index += 1) {
      particles.push(spawnParticle(true))
    }
  }

  function drawParticles(delta: number) {
    ctx.clearRect(0, 0, viewWidth, viewHeight)
    ctx.globalCompositeOperation = 'lighter'

    particles.forEach((particle) => {
      if (!reduced) {
        particle.y -= particle.speed * delta
        particle.x += particle.drift * delta
        particle.phase += delta * 1.6
      }
      if (particle.y < -particle.radius * 2 || particle.x < -60 || particle.x > viewWidth + 60) {
        Object.assign(particle, spawnParticle(false))
      }
      const flicker = reduced ? 1 : 0.72 + Math.sin(particle.phase) * 0.28
      ctx.globalAlpha = Math.max(0, particle.alpha * flicker * alphaScale)
      ctx.drawImage(
        particle.sprite,
        particle.x - particle.radius,
        particle.y - particle.radius,
        particle.radius * 2,
        particle.radius * 2
      )
    })

    ctx.globalAlpha = 1
    ctx.globalCompositeOperation = 'source-over'
  }

  /* 鼠标视差：只写 CSS 变量，实际位移由各层 --depth 决定 */
  function onPointerMove(event: PointerEvent) {
    if (reduced || !finePointer.matches) {
      return
    }
    parallax.tx = (event.clientX / window.innerWidth - 0.5) * 2
    parallax.ty = (event.clientY / window.innerHeight - 0.5) * 2
    parallax.active = true
  }

  function onPointerLeave() {
    parallax.tx = 0
    parallax.ty = 0
  }

  function updateParallax(delta: number) {
    if (!parallax.active) {
      return
    }
    const ease = Math.min(1, delta * 4.5)
    parallax.x += (parallax.tx - parallax.x) * ease
    parallax.y += (parallax.ty - parallax.y) * ease
    scene.style.setProperty('--mx', parallax.x.toFixed(3))
    scene.style.setProperty('--my', parallax.y.toFixed(3))
  }

  /* 噪点颗粒：预生成少量瓦片轮换，避免逐帧重绘 */
  function buildNoiseTiles(count: number) {
    for (let index = 0; index < count; index += 1) {
      const tile = document.createElement('canvas')
      const size = 96
      tile.width = size
      tile.height = size
      const tctx = tile.getContext('2d')
      if (!tctx) {
        return
      }
      const image = tctx.createImageData(size, size)
      for (let offset = 0; offset < image.data.length; offset += 4) {
        const value = (Math.random() * 255) | 0
        image.data[offset] = value
        image.data[offset + 1] = value
        image.data[offset + 2] = value
        image.data[offset + 3] = (Math.random() * 26) | 0
      }
      tctx.putImageData(image, 0, 0)
      noiseTiles.push(tile.toDataURL('image/png'))
    }
  }

  function cycleNoise() {
    if (reduced || noiseTiles.length < 2) {
      return
    }
    noiseIndex = (noiseIndex + 1) % noiseTiles.length
    noise.style.backgroundImage = `url(${noiseTiles[noiseIndex]})`
  }

  /* 主循环与生命周期：页面隐藏时暂停，恢复时续跑 */
  function tick(timestamp: number) {
    if (!running) {
      return
    }
    const delta = Math.min(0.05, (timestamp - lastTime) / 1000 || 0.016)
    lastTime = timestamp
    updateParallax(delta)
    drawParticles(delta)
    rafId = window.requestAnimationFrame(tick)
  }

  function start() {
    if (running) {
      return
    }
    running = true
    lastTime = performance.now()
    root.classList.remove('paused')
    rafId = window.requestAnimationFrame(tick)
    if (!reduced) {
      noiseTimer = window.setInterval(cycleNoise, NOISE_INTERVAL_MS)
    }
  }

  function stop() {
    running = false
    window.cancelAnimationFrame(rafId)
    window.clearInterval(noiseTimer)
    root.classList.add('paused')
  }

  function onResize() {
    window.clearTimeout(resizeTimer)
    resizeTimer = window.setTimeout(() => {
      resizeParticles()
      drawParticles(0)
    }, 150)
  }

  function onVisibilityChange() {
    if (document.hidden) {
      stop()
    } else {
      start()
    }
  }

  function onReduceChange(event: MediaQueryListEvent) {
    reduced = event.matches
    resizeParticles()
    drawParticles(0)
  }

  /* 亮色主题下粒子整体减淡，避免浅底过曝 */
  const themeObserver = new MutationObserver(() => {
    alphaScale = root.dataset.theme === 'light' ? 0.62 : 1
  })

  buildSprites()
  resizeParticles()
  drawParticles(0)
  buildNoiseTiles(reduced ? 1 : 3)
  if (noiseTiles.length > 0) {
    noise.style.backgroundImage = `url(${noiseTiles[0]})`
  }

  window.addEventListener('pointermove', onPointerMove, { passive: true })
  document.addEventListener('pointerleave', onPointerLeave)
  window.addEventListener('resize', onResize)
  document.addEventListener('visibilitychange', onVisibilityChange)
  reduceQuery.addEventListener('change', onReduceChange)
  themeObserver.observe(root, { attributes: true, attributeFilter: ['data-theme'] })
  start()

  return () => {
    stop()
    root.classList.remove('paused')
    window.clearTimeout(resizeTimer)
    window.removeEventListener('pointermove', onPointerMove)
    document.removeEventListener('pointerleave', onPointerLeave)
    window.removeEventListener('resize', onResize)
    document.removeEventListener('visibilitychange', onVisibilityChange)
    reduceQuery.removeEventListener('change', onReduceChange)
    themeObserver.disconnect()
  }
}
