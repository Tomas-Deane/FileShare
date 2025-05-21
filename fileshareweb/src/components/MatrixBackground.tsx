import React, { useRef, useEffect } from 'react';

const MatrixBackground: React.FC = () => {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animationFrameId: number;
    let width = window.innerWidth;
    let height = window.innerHeight;
    canvas.width = width;
    canvas.height = height;

    const fontSize = 26;
    const columns = Math.floor(width / fontSize);
    const drops: number[] = Array(columns).fill(1);
    const characters = 'アァカサタナハマヤャラワガザダバパイィキシチニヒミリヰギジヂビピウゥクスツヌフムユュルグズヅブプエェケセテネヘメレヱゲゼデベペオォコソトノホモヨョロヲゴゾドボポヴッンABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';

    // Store the current character and frame counter for each column
    const currentChars: string[] = Array(columns).fill('');
    const charFrameCounters: number[] = Array(columns).fill(0);
    const charChangeInterval = 20; // Change character every 20 frames

    let frame = 0;
    const draw = () => {
      ctx.fillStyle = 'rgba(0, 0, 0, 0.15)';
      ctx.fillRect(0, 0, width, height);
      ctx.font = `${fontSize}px monospace`;
      ctx.fillStyle = '#00ff41';
      for (let i = 0; i < drops.length; i++) {
        // Only change the character every charChangeInterval frames
        if (charFrameCounters[i] % charChangeInterval === 0) {
          currentChars[i] = characters[Math.floor(Math.random() * characters.length)];
        }
        ctx.fillText(currentChars[i], i * fontSize, drops[i] * fontSize);
        charFrameCounters[i]++;
        if (drops[i] * fontSize > height && Math.random() > 0.975) {
          drops[i] = 0;
          charFrameCounters[i] = 0; // Reset counter when drop resets
        }
        if (frame % 4 === 0) {
          drops[i]++;
        }
      }
      frame++;
      animationFrameId = requestAnimationFrame(draw);
    };

    draw();

    const handleResize = () => {
      width = window.innerWidth;
      height = window.innerHeight;
      canvas.width = width;
      canvas.height = height;
    };
    window.addEventListener('resize', handleResize);

    return () => {
      window.removeEventListener('resize', handleResize);
      cancelAnimationFrame(animationFrameId);
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        width: '100vw',
        height: '100vh',
        zIndex: 0,
        pointerEvents: 'none',
        opacity: 0.5,
      }}
    />
  );
};

export default MatrixBackground; 