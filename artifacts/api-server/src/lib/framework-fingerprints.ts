/**
 * Comprehensive Framework & Technology Fingerprinting Database
 * Detects 50+ frameworks, languages, CMS, and platforms from real HTTP responses
 */

export interface FrameworkSignature {
  name: string;
  category: string;
  language: string;
  signatures: {
    headers?: Record<string, RegExp | string>;
    body?: RegExp[];
    cookies?: string[];
    meta?: string[];
    files?: string[];
  };
  confidence: number;
}

export const FRAMEWORK_SIGNATURES: FrameworkSignature[] = [
  // ═══════════════════════════════════════════════════════
  // PHP FRAMEWORKS
  // ═══════════════════════════════════════════════════════
  {
    name: "Laravel",
    category: "Backend Framework",
    language: "PHP",
    signatures: {
      headers: { "x-laravel-session": /.+/, "set-cookie": /laravel_session/ },
      body: [/laravel/i, /<meta name="csrf-token"/],
      cookies: ["laravel_session", "XSRF-TOKEN"],
    },
    confidence: 95,
  },
  {
    name: "Symfony",
    category: "Backend Framework",
    language: "PHP",
    signatures: {
      headers: { "x-debug-token": /.+/, "x-debug-token-link": /.+/ },
      body: [/symfony/i, /profiler.*symfony/i],
      cookies: ["PHPSESSID"],
    },
    confidence: 90,
  },
  {
    name: "CodeIgniter",
    category: "Backend Framework",
    language: "PHP",
    signatures: {
      body: [/codeigniter/i, /ci_session/],
      cookies: ["ci_session"],
      files: ["/system/core/CodeIgniter.php"],
    },
    confidence: 85,
  },
  {
    name: "CakePHP",
    category: "Backend Framework",
    language: "PHP",
    signatures: {
      body: [/cakephp/i, /cake\.generic/i],
      cookies: ["CAKEPHP"],
    },
    confidence: 85,
  },
  {
    name: "Yii",
    category: "Backend Framework",
    language: "PHP",
    signatures: {
      body: [/yii framework/i, /powered by yii/i],
      cookies: ["YII_CSRF_TOKEN", "_csrf"],
    },
    confidence: 85,
  },

  // ═══════════════════════════════════════════════════════
  // PYTHON FRAMEWORKS
  // ═══════════════════════════════════════════════════════
  {
    name: "Django",
    category: "Backend Framework",
    language: "Python",
    signatures: {
      headers: { "x-frame-options": /SAMEORIGIN/ },
      body: [/csrfmiddlewaretoken/i, /django/i],
      cookies: ["csrftoken", "sessionid"],
    },
    confidence: 95,
  },
  {
    name: "Flask",
    category: "Backend Framework",
    language: "Python",
    signatures: {
      headers: { server: /werkzeug/i },
      body: [/flask/i],
      cookies: ["session"],
    },
    confidence: 90,
  },
  {
    name: "FastAPI",
    category: "Backend Framework",
    language: "Python",
    signatures: {
      headers: { server: /uvicorn/i },
      body: [/fastapi/i, /"detail":/],
    },
    confidence: 90,
  },
  {
    name: "Pyramid",
    category: "Backend Framework",
    language: "Python",
    signatures: {
      body: [/pyramid/i],
      headers: { "x-vhm-root": /.+/ },
    },
    confidence: 80,
  },
  {
    name: "Tornado",
    category: "Backend Framework",
    language: "Python",
    signatures: {
      headers: { server: /tornadoserver/i },
      body: [/tornado/i],
    },
    confidence: 85,
  },

  // ═══════════════════════════════════════════════════════
  // NODE.JS FRAMEWORKS
  // ═══════════════════════════════════════════════════════
  {
    name: "Express.js",
    category: "Backend Framework",
    language: "Node.js",
    signatures: {
      headers: { "x-powered-by": /express/i },
      body: [/express/i],
    },
    confidence: 90,
  },
  {
    name: "NestJS",
    category: "Backend Framework",
    language: "Node.js",
    signatures: {
      body: [/nestjs/i, /@nestjs/],
      headers: { "x-powered-by": /nest/i },
    },
    confidence: 85,
  },
  {
    name: "Koa",
    category: "Backend Framework",
    language: "Node.js",
    signatures: {
      headers: { "x-powered-by": /koa/i },
      body: [/koa/i],
    },
    confidence: 85,
  },
  {
    name: "Hapi.js",
    category: "Backend Framework",
    language: "Node.js",
    signatures: {
      body: [/hapi/i, /@hapi/],
    },
    confidence: 80,
  },
  {
    name: "AdonisJS",
    category: "Backend Framework",
    language: "Node.js",
    signatures: {
      body: [/adonisjs/i, /@adonisjs/],
      cookies: ["adonis-session"],
    },
    confidence: 85,
  },

  // ═══════════════════════════════════════════════════════
  // JAVA FRAMEWORKS
  // ═══════════════════════════════════════════════════════
  {
    name: "Spring Boot",
    category: "Backend Framework",
    language: "Java",
    signatures: {
      headers: { "x-application-context": /.+/ },
      body: [/whitelabel error page/i, /spring/i],
    },
    confidence: 95,
  },
  {
    name: "Spring MVC",
    category: "Backend Framework",
    language: "Java",
    signatures: {
      body: [/spring framework/i, /springframework/],
      cookies: ["JSESSIONID"],
    },
    confidence: 85,
  },
  {
    name: "Struts",
    category: "Backend Framework",
    language: "Java",
    signatures: {
      body: [/struts/i, /\.action/],
      files: ["/struts/", ".action"],
    },
    confidence: 80,
  },
  {
    name: "Apache OFBiz",
    category: "ERP Framework",
    language: "Java",
    signatures: {
      body: [/ofbiz/i, /apache ofbiz/i],
      files: ["/ofbiz/"],
    },
    confidence: 85,
  },

  // ═══════════════════════════════════════════════════════
  // .NET FRAMEWORKS
  // ═══════════════════════════════════════════════════════
  {
    name: "ASP.NET Core",
    category: "Backend Framework",
    language: ".NET",
    signatures: {
      headers: { "x-powered-by": /asp\.net/i, server: /kestrel/i },
      body: [/asp\.net core/i],
      cookies: [".AspNetCore.Session", ".AspNetCore.Antiforgery"],
    },
    confidence: 95,
  },
  {
    name: "ASP.NET",
    category: "Backend Framework",
    language: ".NET",
    signatures: {
      headers: { "x-powered-by": /asp\.net/i, "x-aspnet-version": /.+/ },
      body: [/\.aspx/i, /__VIEWSTATE/],
      cookies: ["ASP.NET_SessionId"],
    },
    confidence: 95,
  },
  {
    name: "Blazor",
    category: "Frontend Framework",
    language: ".NET",
    signatures: {
      body: [/blazor/i, /_framework\/blazor/],
    },
    confidence: 90,
  },

  // ═══════════════════════════════════════════════════════
  // RUBY FRAMEWORKS
  // ═══════════════════════════════════════════════════════
  {
    name: "Ruby on Rails",
    category: "Backend Framework",
    language: "Ruby",
    signatures: {
      headers: { "x-runtime": /.+/, "x-request-id": /.+/ },
      body: [/csrf-token/i, /rails/i],
      cookies: ["_session_id"],
    },
    confidence: 95,
  },
  {
    name: "Sinatra",
    category: "Backend Framework",
    language: "Ruby",
    signatures: {
      headers: { "x-cascade": /pass/i },
      body: [/sinatra/i],
    },
    confidence: 85,
  },

  // ═══════════════════════════════════════════════════════
  // MODERN FULL-STACK FRAMEWORKS
  // ═══════════════════════════════════════════════════════
  {
    name: "Next.js",
    category: "Full-Stack Framework",
    language: "JavaScript",
    signatures: {
      headers: { "x-nextjs-cache": /.+/, "x-nextjs-page": /.+/ },
      body: [/__NEXT_DATA__/, /_next\/static/],
    },
    confidence: 95,
  },
  {
    name: "Nuxt.js",
    category: "Full-Stack Framework",
    language: "JavaScript",
    signatures: {
      body: [/__NUXT__/, /_nuxt\//],
      headers: { "x-nuxt": /.+/ },
    },
    confidence: 95,
  },
  {
    name: "SvelteKit",
    category: "Full-Stack Framework",
    language: "JavaScript",
    signatures: {
      body: [/sveltekit/i, /_app\//],
    },
    confidence: 90,
  },
  {
    name: "Remix",
    category: "Full-Stack Framework",
    language: "JavaScript",
    signatures: {
      body: [/remix/i, /__remix/],
    },
    confidence: 90,
  },

  // ═══════════════════════════════════════════════════════
  // FRONTEND FRAMEWORKS
  // ═══════════════════════════════════════════════════════
  {
    name: "React",
    category: "Frontend Framework",
    language: "JavaScript",
    signatures: {
      body: [/react/i, /data-reactroot/, /_react/],
    },
    confidence: 85,
  },
  {
    name: "Vue.js",
    category: "Frontend Framework",
    language: "JavaScript",
    signatures: {
      body: [/vue/i, /data-v-/, /__vue/],
    },
    confidence: 85,
  },
  {
    name: "Angular",
    category: "Frontend Framework",
    language: "JavaScript",
    signatures: {
      body: [/ng-version/, /angular/i, /_ngcontent/],
    },
    confidence: 85,
  },

  // ═══════════════════════════════════════════════════════
  // CMS PLATFORMS
  // ═══════════════════════════════════════════════════════
  {
    name: "WordPress",
    category: "CMS",
    language: "PHP",
    signatures: {
      body: [/wp-content/i, /wp-includes/i, /wordpress/i],
      meta: ["generator", "WordPress"],
      files: ["/wp-admin/", "/wp-content/"],
    },
    confidence: 95,
  },
  {
    name: "Drupal",
    category: "CMS",
    language: "PHP",
    signatures: {
      headers: { "x-drupal-cache": /.+/, "x-generator": /drupal/i },
      body: [/drupal/i, /sites\/default/],
      meta: ["generator", "Drupal"],
    },
    confidence: 95,
  },
  {
    name: "Joomla",
    category: "CMS",
    language: "PHP",
    signatures: {
      body: [/joomla/i, /\/components\/com_/],
      meta: ["generator", "Joomla"],
    },
    confidence: 95,
  },
  {
    name: "Strapi",
    category: "Headless CMS",
    language: "Node.js",
    signatures: {
      headers: { "x-powered-by": /strapi/i },
      body: [/strapi/i],
    },
    confidence: 90,
  },
  {
    name: "Ghost",
    category: "CMS",
    language: "Node.js",
    signatures: {
      headers: { "x-powered-by": /ghost/i },
      body: [/ghost/i, /content\/themes/],
    },
    confidence: 90,
  },

  // ═══════════════════════════════════════════════════════
  // E-COMMERCE PLATFORMS
  // ═══════════════════════════════════════════════════════
  {
    name: "Magento",
    category: "E-commerce",
    language: "PHP",
    signatures: {
      body: [/magento/i, /mage\/cookies/],
      cookies: ["frontend"],
      files: ["/skin/frontend/"],
    },
    confidence: 95,
  },
  {
    name: "Shopify",
    category: "E-commerce",
    language: "Ruby",
    signatures: {
      headers: { "x-shopify-stage": /.+/ },
      body: [/shopify/i, /cdn\.shopify/],
    },
    confidence: 95,
  },
  {
    name: "WooCommerce",
    category: "E-commerce",
    language: "PHP",
    signatures: {
      body: [/woocommerce/i, /wc-ajax/],
      files: ["/wp-content/plugins/woocommerce/"],
    },
    confidence: 90,
  },
  {
    name: "PrestaShop",
    category: "E-commerce",
    language: "PHP",
    signatures: {
      body: [/prestashop/i],
      cookies: ["PrestaShop"],
    },
    confidence: 90,
  },
  {
    name: "OpenCart",
    category: "E-commerce",
    language: "PHP",
    signatures: {
      body: [/opencart/i, /route=product/],
      cookies: ["OCSESSID"],
    },
    confidence: 90,
  },

  // ═══════════════════════════════════════════════════════
  // ERP / BUSINESS FRAMEWORKS
  // ═══════════════════════════════════════════════════════
  {
    name: "Odoo",
    category: "ERP",
    language: "Python",
    signatures: {
      body: [/odoo/i, /openerp/i],
      cookies: ["session_id"],
      files: ["/web/static/"],
    },
    confidence: 95,
  },
  {
    name: "ERPNext",
    category: "ERP",
    language: "Python",
    signatures: {
      body: [/erpnext/i, /frappe/i],
      files: ["/assets/erpnext/"],
    },
    confidence: 90,
  },
  {
    name: "Dolibarr",
    category: "ERP",
    language: "PHP",
    signatures: {
      body: [/dolibarr/i],
      cookies: ["DOLSESSID"],
    },
    confidence: 90,
  },

  // ═══════════════════════════════════════════════════════
  // CRM PLATFORMS
  // ═══════════════════════════════════════════════════════
  {
    name: "SuiteCRM",
    category: "CRM",
    language: "PHP",
    signatures: {
      body: [/suitecrm/i, /sugar/i],
      files: ["/themes/SuiteP/"],
    },
    confidence: 90,
  },
  {
    name: "EspoCRM",
    category: "CRM",
    language: "PHP",
    signatures: {
      body: [/espocrm/i],
      files: ["/client/modules/crm/"],
    },
    confidence: 90,
  },
];

/**
 * Detect framework from HTTP response
 */
export function detectFramework(
  headers: Record<string, string>,
  body: string,
  cookies: string[]
): { framework: string; language: string; category: string; confidence: number } | null {
  const headersLower = Object.fromEntries(
    Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v.toLowerCase()])
  );

  for (const sig of FRAMEWORK_SIGNATURES) {
    let score = 0;
    let maxScore = 0;

    // Check headers
    if (sig.signatures.headers) {
      for (const [key, pattern] of Object.entries(sig.signatures.headers)) {
        maxScore += 30;
        const headerValue = headersLower[key.toLowerCase()];
        if (headerValue) {
          if (pattern instanceof RegExp) {
            if (pattern.test(headerValue)) score += 30;
          } else if (headerValue.includes(pattern.toLowerCase())) {
            score += 30;
          }
        }
      }
    }

    // Check body patterns
    if (sig.signatures.body) {
      maxScore += 40;
      let bodyMatches = 0;
      for (const pattern of sig.signatures.body) {
        if (pattern.test(body)) bodyMatches++;
      }
      score += (bodyMatches / sig.signatures.body.length) * 40;
    }

    // Check cookies
    if (sig.signatures.cookies) {
      maxScore += 20;
      let cookieMatches = 0;
      for (const cookieName of sig.signatures.cookies) {
        if (cookies.some(c => c.toLowerCase().includes(cookieName.toLowerCase()))) {
          cookieMatches++;
        }
      }
      score += (cookieMatches / sig.signatures.cookies.length) * 20;
    }

    // Check meta tags
    if (sig.signatures.meta) {
      maxScore += 10;
      const metaRegex = new RegExp(`<meta[^>]*name=["']${sig.signatures.meta[0]}["'][^>]*content=["'][^"']*${sig.signatures.meta[1]}`, 'i');
      if (metaRegex.test(body)) score += 10;
    }

    // Calculate confidence
    const confidence = maxScore > 0 ? Math.round((score / maxScore) * 100) : 0;

    // If confidence is high enough, return match
    if (confidence >= 60) {
      return {
        framework: sig.name,
        language: sig.language,
        category: sig.category,
        confidence,
      };
    }
  }

  return null;
}

/**
 * Detect multiple frameworks (some sites use multiple)
 */
export function detectAllFrameworks(
  headers: Record<string, string>,
  body: string,
  cookies: string[]
): Array<{ framework: string; language: string; category: string; confidence: number }> {
  const detected: Array<{ framework: string; language: string; category: string; confidence: number }> = [];
  const headersLower = Object.fromEntries(
    Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v.toLowerCase()])
  );

  for (const sig of FRAMEWORK_SIGNATURES) {
    let score = 0;
    let maxScore = 0;

    if (sig.signatures.headers) {
      for (const [key, pattern] of Object.entries(sig.signatures.headers)) {
        maxScore += 30;
        const headerValue = headersLower[key.toLowerCase()];
        if (headerValue) {
          if (pattern instanceof RegExp) {
            if (pattern.test(headerValue)) score += 30;
          } else if (headerValue.includes(pattern.toLowerCase())) {
            score += 30;
          }
        }
      }
    }

    if (sig.signatures.body) {
      maxScore += 40;
      let bodyMatches = 0;
      for (const pattern of sig.signatures.body) {
        if (pattern.test(body)) bodyMatches++;
      }
      score += (bodyMatches / sig.signatures.body.length) * 40;
    }

    if (sig.signatures.cookies) {
      maxScore += 20;
      let cookieMatches = 0;
      for (const cookieName of sig.signatures.cookies) {
        if (cookies.some(c => c.toLowerCase().includes(cookieName.toLowerCase()))) {
          cookieMatches++;
        }
      }
      score += (cookieMatches / sig.signatures.cookies.length) * 20;
    }

    const confidence = maxScore > 0 ? Math.round((score / maxScore) * 100) : 0;

    if (confidence >= 50) {
      detected.push({
        framework: sig.name,
        language: sig.language,
        category: sig.category,
        confidence,
      });
    }
  }

  // Sort by confidence
  return detected.sort((a, b) => b.confidence - a.confidence);
}
