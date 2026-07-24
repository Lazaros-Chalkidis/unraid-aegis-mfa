/* ============================================================================
   AEGIS MFA
   Copyright (C) 2026 Lazaros Chalkidis
   License: GPLv3
   ========================================================================= */

// navbar button click handler, opens the settings page
function AegisMfaIcon(){
    location.href = '/Settings/AegisMfa';
}

(function(){
    "use strict";

    function setup(){
        var navItem = document.querySelector('.nav-item.AegisMfaIcon');
        if(!navItem){ setTimeout(setup, 500); return; }  // nav item not in the dom yet, retry shortly

        var link = navItem.querySelector('a');
        if(!link) return;

        var img = link.querySelector('img, b.system, i.system, b.fa');
        if(img){
            var svg = document.createElementNS('http://www.w3.org/2000/svg','svg');
            svg.setAttribute('width','16');
            svg.setAttribute('height','16');
            svg.setAttribute('viewBox','0 0 385 421');
            svg.setAttribute('class','system');

            // the keyhole shield, the plugin logo as a filled glyph
            var g = document.createElementNS('http://www.w3.org/2000/svg','g');
            g.setAttribute('transform','translate(0,421) scale(0.1,-0.1)');
            var p = document.createElementNS('http://www.w3.org/2000/svg','path');
            p.setAttribute('d','M963 3996 l-963 -211 0 -845 c0 -936 1 -953 61 -1145 120 -381 447 -804 904 -1170 339 -272 892 -617 990 -618 12 0 279 169 550 348 660 437 1119 955 1273 1437 68 213 72 272 72 1195 l0 798 -882 193 c-486 106 -919 201 -963 211 l-80 17 -962 -210z m1070 -1241 c364 -95 475 -525 204 -788 l-70 -69 27 -381 c15 -210 29 -408 33 -439 l6 -58 -308 0 -308 0 6 58 c4 31 18 229 33 439 l27 381 -70 69 c-343 333 -37 907 420 788z');
            g.appendChild(p);
            svg.appendChild(g);
            img.parentNode.replaceChild(svg, img);

            var iconColor = getComputedStyle(link).color || '#ccc';  // tint the glyph to match the navbar text colour
            svg.setAttribute('fill', iconColor);
        }
    }

    setTimeout(setup, 800);
})();
