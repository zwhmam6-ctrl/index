/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        ink: '#05080F',        // near-black base
        navy: { 900: '#0A1020', 800: '#0F1830', 700: '#16223F', 600: '#22315A' },
        volt: { DEFAULT: '#2F7BFF', soft: '#6EA3FF', deep: '#1B56C9' },
        mist: '#9FB0D0'
      },
      fontFamily: { sans: ['"IBM Plex Sans Arabic"', 'system-ui', 'sans-serif'] }
    }
  },
  plugins: []
}
