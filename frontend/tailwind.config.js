/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        display: ['Outfit', 'Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
      },
      colors: {
        surface: {
          950: '#0b1120',
          900: '#111827',
          850: '#172033',
          800: '#1f2937',
        },
        cyber: {
          teal: '#3b82f6',
          mint: '#93c5fd',
          sky: '#06b6d4',
          amber: '#f59e0b',
          rose: '#f43f5e',
          violet: '#8b5cf6',
        },
      },
      boxShadow: {
        glow: '0 16px 50px rgba(59, 130, 246, 0.16)',
        card: '0 18px 60px rgba(0, 0, 0, 0.24)',
      },
      borderRadius: {
        panel: '12px',
      },
    },
  },
  plugins: [],
};
