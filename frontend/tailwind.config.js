import daisyui from 'daisyui';
import "tailwindcss";



/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {},
  },
  plugins: [daisyui],
  daisyui:{
    themes: [
      {
        guardfile: {
          "primary": "#7c3aed",
          "primary-content": "#ffffff",
          "secondary": "#a78bfa",
          "secondary-content": "#ffffff",
          "accent": "#c084fc",
          "neutral": "#2d2640",
          "neutral-content": "#e8e4f0",
          "base-100": "#f8f6fc",
          "base-200": "#efe9f7",
          "base-300": "#e4ddf0",
          "base-content": "#1f1835",
          "info": "#7dd3fc",
          "success": "#4ade80",
          "warning": "#fbbf24",
          "error": "#f87171",
        },
      },
    ],
  },
};