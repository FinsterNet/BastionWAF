"""
HTML/CSS/JS Slider CAPTCHA Human Verification Page Generator.
"""

from .captcha import generate_challenge_token


def render_captcha_page(client_ip: str, target_path: str = "/", reason: str = "Suspicious traffic anomaly detected") -> str:
    """
    Renders an interactive, responsive Slider CAPTCHA verification page.
    """
    token, target_x = generate_challenge_token()

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Verification | Bastion WAF</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {{
            --bg-dark: #070a13;
            --bg-card: #0e1424;
            --border-color: #1e2d4a;
            --text-main: #f1f5f9;
            --text-muted: #94a3b8;
            --accent-cyan: #06b6d4;
            --accent-blue: #3b82f6;
            --accent-green: #10b981;
            --accent-red: #ef4444;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; }}
        body {{
            background-color: var(--bg-dark);
            color: var(--text-main);
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            padding: 20px;
        }}
        .challenge-box {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 14px;
            padding: 30px 25px;
            width: 100%;
            max-width: 420px;
            box-shadow: 0 10px 40px rgba(0, 0, 0, 0.6), 0 0 20px rgba(6, 182, 212, 0.15);
            text-align: center;
        }}
        .badge-header {{
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background: rgba(6, 182, 212, 0.12);
            color: var(--accent-cyan);
            border: 1px solid rgba(6, 182, 212, 0.3);
            border-radius: 20px;
            padding: 5px 14px;
            font-size: 0.8rem;
            font-weight: 600;
            margin-bottom: 15px;
        }}
        h2 {{ font-size: 1.35rem; margin-bottom: 8px; color: #fff; }}
        p.subtitle {{ font-size: 0.85rem; color: var(--text-muted); margin-bottom: 20px; }}
        
        .puzzle-stage {{
            position: relative;
            width: 100%;
            height: 150px;
            border-radius: 8px;
            overflow: hidden;
            border: 1px solid var(--border-color);
            background: linear-gradient(135deg, #0b1329 0%, #1e293b 100%);
            margin-bottom: 20px;
            user-select: none;
        }}
        .grid-pattern {{
            position: absolute;
            inset: 0;
            background-size: 20px 20px;
            background-image: linear-gradient(to right, rgba(255,255,255,0.05) 1px, transparent 1px),
                              linear-gradient(to bottom, rgba(255,255,255,0.05) 1px, transparent 1px);
        }}
        .puzzle-target-slot {{
            position: absolute;
            top: 45px;
            left: {target_x}px;
            width: 46px;
            height: 46px;
            background: rgba(0, 0, 0, 0.6);
            border: 2px dashed rgba(6, 182, 212, 0.8);
            border-radius: 8px;
            box-shadow: inset 0 0 10px rgba(0,0,0,0.8);
        }}
        .puzzle-piece {{
            position: absolute;
            top: 45px;
            left: 0px;
            width: 46px;
            height: 46px;
            background: linear-gradient(135deg, var(--accent-cyan), var(--accent-blue));
            border: 2px solid #fff;
            border-radius: 8px;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.5), 0 0 10px rgba(6, 182, 212, 0.5);
            display: flex;
            align-items: center;
            justify-content: center;
            color: #fff;
            cursor: pointer;
            z-index: 10;
        }}
        .slider-track {{
            position: relative;
            height: 48px;
            background: #070c18;
            border: 1px solid var(--border-color);
            border-radius: 24px;
            overflow: hidden;
            display: flex;
            align-items: center;
            user-select: none;
        }}
        .slider-progress {{
            position: absolute;
            left: 0;
            top: 0;
            bottom: 0;
            width: 0%;
            background: rgba(6, 182, 212, 0.15);
            border-right: 1px solid var(--accent-cyan);
        }}
        .slider-prompt {{
            width: 100%;
            text-align: center;
            font-size: 0.82rem;
            color: var(--text-muted);
            pointer-events: none;
        }}
        .slider-handle {{
            position: absolute;
            left: 2px;
            top: 2px;
            width: 42px;
            height: 42px;
            border-radius: 50%;
            background: linear-gradient(135deg, var(--accent-cyan), var(--accent-blue));
            display: flex;
            align-items: center;
            justify-content: center;
            color: #fff;
            cursor: grab;
            box-shadow: 0 2px 8px rgba(0,0,0,0.4);
            transition: transform 0.05s ease;
            z-index: 5;
        }}
        .slider-handle:active {{ cursor: grabbing; }}
        
        .status-msg {{
            font-size: 0.8rem;
            min-height: 20px;
            margin-top: 15px;
            font-weight: 500;
        }}
        .status-msg.error {{ color: var(--accent-red); }}
        .status-msg.success {{ color: var(--accent-green); }}

        .footer-note {{
            font-size: 0.75rem;
            color: #475569;
            margin-top: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
    </style>
</head>
<body>

    <div class="challenge-box">
        <div class="badge-header">
            <i class="fa-solid fa-shield-halved"></i> Bastion Security Shield
        </div>
        <h2>Human Verification</h2>
        <p class="subtitle">Drag the slider below to align the puzzle piece and proceed.</p>

        <!-- Visual Stage -->
        <div class="puzzle-stage">
            <div class="grid-pattern"></div>
            <div class="puzzle-target-slot" id="targetSlot"></div>
            <div class="puzzle-piece" id="puzzlePiece"><i class="fa-solid fa-puzzle-piece"></i></div>
        </div>

        <!-- Slider Bar -->
        <div class="slider-track" id="sliderTrack">
            <div class="slider-progress" id="sliderProgress"></div>
            <div class="slider-prompt" id="sliderPrompt">Slide right to complete &rarr;</div>
            <div class="slider-handle" id="sliderHandle">
                <i class="fa-solid fa-angles-right"></i>
            </div>
        </div>

        <div class="status-msg" id="statusMsg"></div>

        <div class="footer-note">
            <span>Client: {client_ip}</span>
            <span>Reason: Adaptive Challenge</span>
        </div>
    </div>

    <script>
        const handle = document.getElementById('sliderHandle');
        const track = document.getElementById('sliderTrack');
        const progress = document.getElementById('sliderProgress');
        const piece = document.getElementById('puzzlePiece');
        const prompt = document.getElementById('sliderPrompt');
        const statusMsg = document.getElementById('statusMsg');

        let isDragging = false;
        let startX = 0;
        let startTime = 0;
        let trajectory = [];
        const challengeToken = "{token}";
        const maxSlide = track.clientWidth - handle.clientWidth - 4;

        function onStart(e) {{
            isDragging = true;
            startX = e.type.includes('touch') ? e.touches[0].clientX : e.clientX;
            startTime = Date.now();
            trajectory = [{{ x: 0, t: 0 }}];
            statusMsg.textContent = '';
            statusMsg.className = 'status-msg';
            prompt.style.opacity = '0.3';
        }}

        function onMove(e) {{
            if (!isDragging) return;
            const currentX = e.type.includes('touch') ? e.touches[0].clientX : e.clientX;
            const deltaX = Math.max(0, Math.min(maxSlide, currentX - startX));
            
            handle.style.left = `${{deltaX + 2}}px`;
            progress.style.width = `${{(deltaX / maxSlide) * 100}}%`;
            
            // Map slide to puzzle piece (proportional to puzzle stage width)
            const pieceOffset = (deltaX / maxSlide) * (track.clientWidth - 50);
            piece.style.left = `${{pieceOffset}}px`;

            trajectory.push({{ x: deltaX, t: Date.now() - startTime }});
        }}

        async function onEnd() {{
            if (!isDragging) return;
            isDragging = false;
            const duration = Date.now() - startTime;
            const finalX = (parseFloat(handle.style.left) || 0);
            const mappedPieceX = (finalX / maxSlide) * (track.clientWidth - 50);

            statusMsg.textContent = 'Verifying interaction dynamics...';

            try {{
                const res = await fetch('/__bastion_captcha_verify__', {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify({{
                        token: challengeToken,
                        user_x: mappedPieceX,
                        duration_ms: duration,
                        trajectory_count: trajectory.length
                    }})
                }});
                const data = await res.json();
                
                if (data.status === 'ok') {{
                    statusMsg.textContent = '✓ Verification successful! Redirecting...';
                    statusMsg.className = 'status-msg success';
                    handle.style.background = 'var(--accent-green)';
                    handle.innerHTML = '<i class="fa-solid fa-check"></i>';
                    setTimeout(() => {{
                        window.location.reload();
                    }}, 600);
                }} else {{
                    statusMsg.textContent = '✗ ' + (data.message || 'Verification failed. Please try again.');
                    statusMsg.className = 'status-msg error';
                    resetSlider();
                }}
            }} catch (err) {{
                statusMsg.textContent = 'Network error during verification.';
                statusMsg.className = 'status-msg error';
                resetSlider();
            }}
        }}

        function resetSlider() {{
            setTimeout(() => {{
                handle.style.left = '2px';
                progress.style.width = '0%';
                piece.style.left = '0px';
                prompt.style.opacity = '1';
            }}, 800);
        }}

        // Mouse events
        handle.addEventListener('mousedown', onStart);
        window.addEventListener('mousemove', onMove);
        window.addEventListener('mouseup', onEnd);

        // Touch events
        handle.addEventListener('touchstart', onStart, {{ passive: true }});
        window.addEventListener('touchmove', onMove, {{ passive: true }});
        window.addEventListener('touchend', onEnd);
    </script>
</body>
</html>
"""
    return html_content
