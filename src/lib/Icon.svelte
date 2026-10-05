<script lang="ts">
  export let name: string;
  export let size = 18;
  export let strokeWidth = 1.8;
  export let label = '';
</script>

<svg
  width={size}
  height={size}
  viewBox="0 0 24 24"
  fill="none"
  stroke="currentColor"
  stroke-width={strokeWidth}
  stroke-linecap="round"
  stroke-linejoin="round"
  role={label ? 'img' : undefined}
  aria-label={label || undefined}
  aria-hidden={label ? undefined : 'true'}
  focusable="false"
>
  {#if name === 'search'}
    <circle cx="11" cy="11" r="6.5" />
    <path d="m16 16 4.5 4.5" />
  {:else if name === 'plus'}
    <path d="M12 5v14M5 12h14" />
  {:else if name === 'lock'}
    <rect x="5" y="10" width="14" height="10" rx="2" />
    <path d="M8 10V7a4 4 0 0 1 8 0v3M12 14v2" />
  {:else if name === 'unlock'}
    <rect x="5" y="10" width="14" height="10" rx="2" />
    <path d="M8 10V7a4 4 0 0 1 7.2-2.4M12 14v2" />
  {:else if name === 'star'}
    <path d="m12 3 2.8 5.7 6.2.9-4.5 4.4 1.1 6.2-5.6-2.9-5.6 2.9 1.1-6.2L3 9.6l6.2-.9L12 3Z" />
  {:else if name === 'settings'}
    <path d="M12 3.5v2M12 18.5v2M20.5 12h-2M5.5 12h-2M18 6l-1.4 1.4M7.4 16.6 6 18M18 18l-1.4-1.4M7.4 7.4 6 6" />
    <circle cx="12" cy="12" r="4" />
  {:else if name === 'eye'}
    <path d="M2.5 12s3.5-5 9.5-5 9.5 5 9.5 5-3.5 5-9.5 5-9.5-5-9.5-5Z" />
    <circle cx="12" cy="12" r="2.2" />
  {:else if name === 'eye-off'}
    <path d="m3 3 18 18M10.6 6.9A10.8 10.8 0 0 1 12 6.8c6 0 9.5 5.2 9.5 5.2a15.4 15.4 0 0 1-3.3 3.5M6.6 6.7C4 8.2 2.5 12 2.5 12s3.5 5.2 9.5 5.2c.8 0 1.5-.1 2.2-.3" />
  {:else if name === 'copy'}
    <rect x="8" y="8" width="11" height="12" rx="2" />
    <path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h2" />
  {:else if name === 'edit'}
    <path d="m4 16.5-.8 4.3 4.3-.8L19 8.5 15.5 5 4 16.5Z" />
    <path d="m13.8 6.7 3.5 3.5" />
  {:else if name === 'trash'}
    <path d="M4 7h16M10 11v6M14 11v6M6.5 7l.7 13h9.6l.7-13M9 7V4h6v3" />
  {:else if name === 'chevron-down'}
    <path d="m6 9 6 6 6-6" />
  {:else if name === 'arrow-right'}
    <path d="M5 12h14M13 6l6 6-6 6" />
  {:else if name === 'shield'}
    <path d="M12 3 19 6v5c0 4.6-2.9 8-7 10-4.1-2-7-5.4-7-10V6l7-3Z" />
    <path d="m9 12 2 2 4-4" />
  {:else if name === 'spark'}
    <path d="m12 3 1.3 5.7L19 10l-5.7 1.3L12 17l-1.3-5.7L5 10l5.7-1.3L12 3ZM19 16l.6 2.4L22 19l-2.4.6L19 22l-.6-2.4L16 19l2.4-.6L19 16Z" />
  {:else if name === 'external'}
    <path d="M14 5h5v5M19 5l-8 8" />
    <path d="M18 13v5a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h5" />
  {:else if name === 'menu'}
    <path d="M4 6h16M4 12h16M4 18h16" />
  {:else if name === 'check'}
    <path d="m5 12 4 4L19 6" />
  {:else if name === 'close'}
    <path d="m6 6 12 12M18 6 6 18" />
  {:else if name === 'key'}
    <circle cx="8" cy="15" r="4" />
    <path d="m11 12 8-8M15 8l2 2M17 6l2 2" />
  {:else if name === 'info'}
    <circle cx="12" cy="12" r="9" />
    <path d="M12 11v5M12 8h.01" />
  {:else if name === 'refresh'}
    <path d="M20 11a8 8 0 0 0-14.5-4.5L4 8" />
    <path d="M4 4v4h4M4 13a8 8 0 0 0 14.5 4.5L20 16" />
    <path d="M20 20v-4h-4" />
  {/if}
</svg>
