"use client";

/*
 * Social hover grid adapted from:
 * From Uiverse.io by Praashoo7 - https://uiverse.io/Praashoo7/smooth-crab-52
 * MIT License, Copyright (c) Praashoo7 (Prashant)
 *
 * Changes: 3 links in one row instead of the 3x3 grid, React/JSX, class names
 * prefixed with "sx-" (styles live in globals.css), real links + labels for
 * keyboard and screen readers, icons always visible on touch screens.
 */

import { usePathname } from "next/navigation";
import { LINKEDIN_URL } from "./TopBar";

const INSTAGRAM_URL = "https://www.instagram.com/daneshdhanjall/";
const GITHUB_URL = "https://github.com/DanishDhanjal15";

export function SiteFooter() {
  const path = usePathname();
  if (path === "/login") return null;
  return (
    <footer className="border-t border-line mt-10">
      <div className="max-w-5xl mx-auto px-4 py-10 flex flex-col sm:flex-row items-center justify-between gap-8">
        <div className="text-center sm:text-left">
          <h2 className="text-[18px] font-semibold text-ink">Connect with Danish</h2>
          <p className="text-[13px] text-muted mt-1.5 max-w-xs">Questions, feedback or a protocol you want explained next? Say hi.</p>
          <p className="text-[12px] text-muted mt-4">© Protocols by Danish</p>
        </div>
        <SocialGrid />
      </div>
    </footer>
  );
}

function SocialGrid() {
  return (
    <div className="sx-main">
      <a className="sx-card" href={INSTAGRAM_URL} target="_blank" rel="noopener noreferrer" aria-label="Danish on Instagram" title="Instagram">
        <svg fillRule="nonzero" height="30px" width="30px" viewBox="0,0,256,256" xmlns="http://www.w3.org/2000/svg" className="sx-instagram" aria-hidden="true">
          <g transform="scale(8,8)">
            <path d="M11.46875,5c-3.55078,0 -6.46875,2.91406 -6.46875,6.46875v9.0625c0,3.55078 2.91406,6.46875 6.46875,6.46875h9.0625c3.55078,0 6.46875,-2.91406 6.46875,-6.46875v-9.0625c0,-3.55078 -2.91406,-6.46875 -6.46875,-6.46875zM11.46875,7h9.0625c2.47266,0 4.46875,1.99609 4.46875,4.46875v9.0625c0,2.47266 -1.99609,4.46875 -4.46875,4.46875h-9.0625c-2.47266,0 -4.46875,-1.99609 -4.46875,-4.46875v-9.0625c0,-2.47266 1.99609,-4.46875 4.46875,-4.46875zM21.90625,9.1875c-0.50391,0 -0.90625,0.40234 -0.90625,0.90625c0,0.50391 0.40234,0.90625 0.90625,0.90625c0.50391,0 0.90625,-0.40234 0.90625,-0.90625c0,-0.50391 -0.40234,-0.90625 -0.90625,-0.90625zM16,10c-3.30078,0 -6,2.69922 -6,6c0,3.30078 2.69922,6 6,6c3.30078,0 6,-2.69922 6,-6c0,-3.30078 -2.69922,-6 -6,-6zM16,12c2.22266,0 4,1.77734 4,4c0,2.22266 -1.77734,4 -4,4c-2.22266,0 -4,-1.77734 -4,-4c0,-2.22266 1.77734,-4 4,-4z" />
          </g>
        </svg>
      </a>
      <a className="sx-card" href={LINKEDIN_URL} target="_blank" rel="noopener noreferrer" aria-label="Danish on LinkedIn" title="LinkedIn">
        <svg height="26px" width="26px" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" className="sx-linkedin" aria-hidden="true">
          <path d="M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.445-2.136 2.939v5.667H9.351V9h3.414v1.561h.046c.477-.9 1.637-1.85 3.37-1.85 3.601 0 4.267 2.37 4.267 5.455v6.286zM5.337 7.433a2.062 2.062 0 1 1 0-4.125 2.062 2.062 0 0 1 0 4.125zM7.119 20.452H3.555V9h3.564v11.452zM22.225 0H1.771C.792 0 0 .774 0 1.729v20.542C0 23.227.792 24 1.771 24h20.451C23.2 24 24 23.227 24 22.271V1.729C24 .774 23.2 0 22.222 0h.003z" />
        </svg>
      </a>
      <a className="sx-card" href={GITHUB_URL} target="_blank" rel="noopener noreferrer" aria-label="Danish on GitHub" title="GitHub">
        <svg height="30px" width="30px" viewBox="0 0 30 30" xmlns="http://www.w3.org/2000/svg" className="sx-github" aria-hidden="true">
          <path d="M15,3C8.373,3,3,8.373,3,15c0,5.623,3.872,10.328,9.092,11.63C12.036,26.468,12,26.28,12,26.047v-2.051 c-0.487,0-1.303,0-1.508,0c-0.821,0-1.551-0.353-1.905-1.009c-0.393-0.729-0.461-1.844-1.435-2.526 c-0.289-0.227-0.069-0.486,0.264-0.451c0.615,0.174,1.125,0.596,1.605,1.222c0.478,0.627,0.703,0.769,1.596,0.769 c0.433,0,1.081-0.025,1.691-0.121c0.328-0.833,0.895-1.6,1.588-1.962c-3.996-0.411-5.903-2.399-5.903-5.098 c0-1.162,0.495-2.286,1.336-3.233C9.053,10.647,8.706,8.73,9.435,8c1.798,0,2.885,1.166,3.146,1.481C13.477,9.174,14.461,9,15.495,9 c1.036,0,2.024,0.174,2.922,0.483C18.675,9.17,19.763,8,21.565,8c0.732,0.731,0.381,2.656,0.102,3.594 c0.836,0.945,1.328,2.066,1.328,3.226c0,2.697-1.904,4.684-5.894,5.097C18.199,20.49,19,22.1,19,23.313v2.734 c0,0.104-0.023,0.179-0.035,0.268C23.641,24.676,27,20.236,27,15C27,8.373,21.627,3,15,3z" />
        </svg>
      </a>
      <p className="sx-text" aria-hidden="true">HOVER FOR SOCIAL</p>
      <div className="sx-back" aria-hidden="true" />
    </div>
  );
}
