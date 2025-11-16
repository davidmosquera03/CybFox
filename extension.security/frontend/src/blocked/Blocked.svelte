<script></script>

<style>
  :global(body) { margin: 0; background: #d50000; height: 100vh; }
  .wrap {
    width: 100vw; height: 100vh;
    display:flex; align-items:center; justify-content:center;
    position: relative; overflow: hidden; color: white; font-family: sans-serif;
  }

  /* fondo warning */
  .warning-bg {
    position:absolute; inset:0;
    display:flex; align-items:center; justify-content:center;
    opacity:0.12; pointer-events:none; z-index:1;
  }

  .triangle {
    width: 0; height: 0;
    border-left: 220px solid transparent;
    border-right: 220px solid transparent;
    border-bottom: 340px solid white;
    filter: blur(1px);
  }

  .exclam {
    position:absolute; top: 85px; width: 36px; height: 140px;
    background: white; border-radius: 6px; opacity:0.9;
  }

  .dot {
    position:absolute; top: 240px; width: 36px; height: 36px;
    background: white; border-radius:50%; opacity:0.9;
  }

  .front {
    position: relative; z-index: 10; text-align:center;
  }

  h1 { margin:0; font-size: 2.4rem; letter-spacing: 0.02em; }
  p  { margin-top: 8px; opacity: 0.95; }

  @media (max-width: 600px) {
    .triangle { border-left-width: 120px; border-right-width: 120px; border-bottom-width: 200px; }
    .exclam { width: 22px; height: 90px; top: 45px; }
    .dot { width:22px; height:22px; top:140px; }
    h1 { font-size: 1.6rem; }
  }
</style>

<div class="wrap">
  <div class="warning-bg">
    <div class="triangle"></div>
    <div class="exclam"></div>
    <div class="dot"></div>
  </div>

  <div class="front">
    <h1>Sitio bloqueado</h1>
    <p>La página ha sido bloqueada por la extensión</p>
  </div>
</div>
