import mermaid from 'mermaid';

// Mermaid Markdown Plugin for markdown-it
export default function mermaidMarkdownPlugin(md) {
  // Load preferences from localStorage
  const theme = localStorage.getItem('mermaid-theme') || 'default';
  const ganttAxisFormat = localStorage.getItem('gantt-axis-format') || '%Y-%m-%d';

  // Initialize Mermaid with only non-default parameters
  mermaid.initialize({
    startOnLoad: false, // Prevent auto-rendering; markdown-it handles rendering
    theme,
    gantt: {
      axisFormat: ganttAxisFormat
    }
  });

  // URL Sanitization
  const SAFE_URL = 'about:blank';
  const sanitizeUrl = (url) => {
    if (!url) return SAFE_URL;

    const controlChars = /[\x00-\x1F\x7F-\x9F\u2000-\u200D\uFEFF]/g;
    const htmlEntities = /&#(\w+)(?:;)?/g;
    const newlineTab = /&(newline|tab);/gi;
    const protocolMatch = /^[^:]+:/i;
    const relativeStart = ['.', '/'];
    const dangerousProtocols = /^(javascript|data|vbscript)/i;

    let cleaned = url
      .replace(controlChars, '')
      .replace(htmlEntities, (_, code) => String.fromCharCode(code))
      .replace(newlineTab, '')
      .replace(controlChars, '')
      .trim();

    if (!cleaned) return SAFE_URL;
    if (relativeStart.includes(cleaned[0])) return cleaned;

    const protocol = cleaned.match(protocolMatch)?.[0] || '';
    return dangerousProtocols.test(protocol) ? SAFE_URL : cleaned;
  };

  // Apply URL sanitization to links
  const defaultLinkOpen = md.renderer.rules.link_open || ((tokens, idx, options, env, self) => self.renderToken(tokens, idx, options));
  md.renderer.rules.link_open = (tokens, idx, options, env, self) => {
    const token = tokens[idx];
    const href = token.attrGet('href');
    if (href) {
      token.attrSet('href', sanitizeUrl(href));
    }
    return defaultLinkOpen(tokens, idx, options, env, self);
  };

  // Inject Mermaid-specific styles
  const styles = `
    .mermaid .edgePath path { stroke-width: 3; }
    .mermaid .section0 rect, .mermaid .section0 path, .mermaid .section0 circle { fill: #69c; }
    .mermaid .sectionRoot rect, .mermaid .sectionRoot path, .mermaid .sectionRoot circle { fill: #f66; }
    .mermaid .eventWrapper { filter: brightness(120%); }
  `;
  if (typeof document !== 'undefined') {
    const styleElement = document.createElement('style');
    styleElement.textContent = styles;
    document.head.appendChild(styleElement);
  }

  // Fence rule for Mermaid diagrams
  const defaultFence = md.renderer.rules.fence || ((tokens, idx, opts, env, self) => self.renderToken(tokens, idx, opts));
  md.renderer.rules.fence = (tokens, idx, opts, env, self) => {
    const token = tokens[idx];
    const info = token.info.trim().split(/\s+/)[0];
    const content = token.content.trim();

    // Check if the block is a Mermaid diagram
    const isMermaid =
      info === 'mermaid' ||
      /^(gantt|sequenceDiagram|graph\s+(?:TB|BT|RL|LR|TD)?)/i.test(content.split('\n')[0].trim());

    if (isMermaid) {
      try {
        // Validate Mermaid syntax
        mermaid.parse(content);
        return `<div class="mermaid">${content}</div>`;
      } catch (err) {
        const message = err.message || 'Invalid Mermaid syntax';
        return `<pre>${message}</pre>`;
      }
    }

    // Fall back to default fence rendering
    return defaultFence(tokens, idx, opts, env, self);
  };

  // Attach Mermaid to markdown-it instance
  md.mermaid = mermaid;
}
