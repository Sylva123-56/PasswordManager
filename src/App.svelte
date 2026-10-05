<script lang="ts">
  import { onDestroy, onMount } from 'svelte';
  import { open, save } from '@tauri-apps/plugin-dialog';
  import Icon from './lib/Icon.svelte';
  import { api, errorMessage } from './lib/api';
  import type {
    AppSettings,
    AppState,
    EntryInput,
    EntrySummary,
    PasswordEntry,
    PasswordOptions,
    View,
  } from './lib/types';

  type Mode = 'loading' | 'setup' | 'unlock' | 'main';
  type SettingsTab = 'safety' | 'account';

  const emptyForm = (): EntryInput => ({
    title: '',
    username: '',
    password: '',
    url: '',
    notes: '',
    tags: [],
    favorite: false,
  });

  const defaultGenerator: PasswordOptions = {
    length: 20,
    includeUppercase: true,
    includeLowercase: true,
    includeNumbers: true,
    includeSymbols: true,
    excludeAmbiguous: true,
  };

  let mode: Mode = 'loading';
  let appState: AppState | null = null;
  let settings: AppSettings = { autoLockSeconds: 900, clipboardClearSeconds: 30 };
  let settingsDraft: AppSettings = { ...settings };
  let settingsTab: SettingsTab = 'safety';

  let setupPassword = '';
  let setupConfirmation = '';
  let unlockPassword = '';
  let showSetupPassword = false;
  let showUnlockPassword = false;
  let selectedPath: string | null = null;

  let view: View = 'all';
  let activeTag: string | null = null;
  let searchQuery = '';
  let sortMode = 'updated_desc';
  let entries: EntrySummary[] = [];
  let selectedId: string | null = null;
  let selectedEntry: PasswordEntry | null = null;
  let showDetailPassword = false;

  let editorOpen = false;
  let editingId: string | null = null;
  let form: EntryInput = emptyForm();
  let formSnapshot = '';
  let showFormPassword = false;
  let generatorOpen = false;
  let generatorOptions: PasswordOptions = { ...defaultGenerator };
  let generatedPassword = '';

  let settingsOpen = false;
  let oldMasterPassword = '';
  let newMasterPassword = '';
  let newMasterConfirmation = '';

  let busy = false;
  let detailBusy = false;
  let error = '';
  let toast = '';
  let toastTimer: ReturnType<typeof setTimeout> | undefined;
  let autoLockRemaining: number | null = null;
  let statusTimer: ReturnType<typeof setInterval> | undefined;
  let lastActivitySignal = 0;

  $: isFormDirty = editorOpen && JSON.stringify(form) !== formSnapshot;
  $: allTags = Array.from(new Set(entries.flatMap((entry) => entry.tags))).sort((a, b) => a.localeCompare(b, 'zh-CN'));
  $: selectedSummary = selectedId ? entries.find((entry) => entry.id === selectedId) : null;
  $: passwordStrength = strengthFor(editingId ? form.password : setupPassword);

  function strengthFor(value: string): { score: number; label: string; tone: string } {
    if (!value) return { score: 0, label: '还没有输入', tone: 'empty' };
    let score = 0;
    if (value.length >= 8) score += 1;
    if (value.length >= 14) score += 1;
    if (/[a-z]/.test(value) && /[A-Z]/.test(value)) score += 1;
    if (/\d/.test(value)) score += 1;
    if (/[^A-Za-z0-9]/.test(value)) score += 1;
    if (score <= 1) return { score, label: '偏弱', tone: 'weak' };
    if (score <= 3) return { score, label: '可以更强', tone: 'fair' };
    return { score, label: '强度不错', tone: 'strong' };
  }

  function showToast(message: string) {
    toast = message;
    if (toastTimer) clearTimeout(toastTimer);
    toastTimer = setTimeout(() => (toast = ''), 3200);
  }

  function setError(value: unknown, fallback = '操作失败，请稍后重试。') {
    error = errorMessage(value, fallback);
  }

  function clearError() {
    error = '';
  }

  function formatRemaining(seconds: number | null): string {
    if (seconds === null) return '自动锁定已关闭';
    const minutes = Math.floor(seconds / 60);
    const remainder = seconds % 60;
    return '将在 ' + minutes + ':' + String(remainder).padStart(2, '0') + ' 后锁定';
  }

  function formatDate(value: string): string {
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return '刚刚';
    const diff = Date.now() - date.getTime();
    if (diff < 60_000) return '刚刚修改';
    if (diff < 3_600_000) return Math.max(1, Math.floor(diff / 60_000)) + ' 分钟前';
    if (diff < 86_400_000) return Math.floor(diff / 3_600_000) + ' 小时前';
    if (diff < 7 * 86_400_000) return Math.floor(diff / 86_400_000) + ' 天前';
    return date.toLocaleDateString('zh-CN', { month: 'short', day: 'numeric' });
  }

  function displayInitials(entry: EntrySummary | PasswordEntry): string {
    const words = entry.title.trim().split(/\s+/).filter(Boolean);
    if (words.length > 1) return (words[0][0] + words[1][0]).toUpperCase();
    return entry.title.trim().slice(0, 2).toUpperCase() || '??';
  }

  function domainFromUrl(url: string): string {
    if (!url) return '';
    try {
      return new URL(url.includes('://') ? url : 'https://' + url).hostname.replace(/^www\./, '');
    } catch {
      return url.replace(/^https?:\/\//, '').split('/')[0];
    }
  }

  async function bootstrap() {
    try {
      const [nextState, nextSettings] = await Promise.all([api.getAppState(), api.getSettings()]);
      appState = nextState;
      settings = nextSettings;
      settingsDraft = { ...nextSettings };
      mode = nextState.vaultExists ? 'unlock' : 'setup';
    } catch (cause) {
      setError(cause, '无法启动本地密码库，请检查应用数据目录权限。');
      mode = 'unlock';
    }
  }

  async function refreshStatus() {
    if (mode === 'loading') return;
    try {
      const nextState = await api.getAppState();
      appState = nextState;
      autoLockRemaining = nextState.autoLockSecondsRemaining;
      if (mode === 'main' && nextState.locked) {
        resetSensitiveUi();
        mode = 'unlock';
        unlockPassword = '';
        showToast('密码库已锁定');
      }
    } catch {
      // The next poll can recover transient IPC failures without interrupting the UI.
    }
  }

  async function enterMain() {
    mode = 'main';
    clearError();
    setupPassword = '';
    setupConfirmation = '';
    unlockPassword = '';
    selectedPath = null;
    await refreshStatus();
    await loadEntries();
  }

  async function handleCreateVault() {
    clearError();
    if (!setupPassword.trim()) {
      setError('请先设置主密码。');
      return;
    }
    if (setupPassword !== setupConfirmation) {
      setError('两次输入的主密码不一致。');
      return;
    }
    busy = true;
    try {
      await api.createVault(setupPassword);
      await enterMain();
      showToast('密码库已创建并解锁');
    } catch (cause) {
      setError(cause);
    } finally {
      busy = false;
    }
  }

  async function chooseVault() {
    clearError();
    try {
      const selected = await open({
        multiple: false,
        directory: false,
        filters: [{ name: 'Vaultroom 密码库', extensions: ['pmvault', '1', '2', '3'] }],
      });
      if (typeof selected === 'string') {
        selectedPath = selected;
        showToast('已选择 ' + selected.split(/[\\/]/).pop());
      }
    } catch (cause) {
      setError(cause, '无法打开文件选择器。');
    }
  }

  async function returnToDefaultVault() {
    clearError();
    try {
      await api.closeVault();
      selectedPath = null;
      appState = await api.getAppState();
      showToast('已切回默认密码库');
    } catch (cause) {
      setError(cause);
    }
  }

  async function handleUnlock() {
    clearError();
    if (!unlockPassword.trim()) {
      setError('请输入主密码。');
      return;
    }
    busy = true;
    try {
      await api.openVault(unlockPassword, selectedPath);
      await enterMain();
      showToast('密码库已解锁');
    } catch (cause) {
      setError(cause);
    } finally {
      busy = false;
    }
  }

  async function loadEntries() {
    if (mode !== 'main') return;
    try {
      entries = await api.listEntries(
        searchQuery,
        { scope: view === 'favorites' ? 'favorites' : 'all', tag: activeTag },
        view === 'recent' ? 'updated_desc' : sortMode,
      );
      if (selectedId && !entries.some((entry) => entry.id === selectedId)) {
        selectedId = null;
        selectedEntry = null;
      }
    } catch (cause) {
      if (mode === 'main') setError(cause);
    }
  }

  async function selectEntry(id: string) {
    selectedId = id;
    selectedEntry = null;
    showDetailPassword = false;
    detailBusy = true;
    clearError();
    try {
      selectedEntry = await api.getEntry(id);
    } catch (cause) {
      setError(cause);
      selectedId = null;
    } finally {
      detailBusy = false;
    }
  }

  function openNewEntry() {
    clearError();
    editingId = null;
    form = emptyForm();
    formSnapshot = JSON.stringify(form);
    showFormPassword = false;
    editorOpen = true;
  }

  function openEditEntry() {
    if (!selectedEntry) return;
    clearError();
    editingId = selectedEntry.id;
    form = {
      title: selectedEntry.title,
      username: selectedEntry.username,
      password: selectedEntry.password,
      url: selectedEntry.url,
      notes: selectedEntry.notes,
      tags: [...selectedEntry.tags],
      favorite: selectedEntry.favorite,
      customFields: { ...selectedEntry.customFields },
    };
    formSnapshot = JSON.stringify(form);
    showFormPassword = false;
    editorOpen = true;
  }

  function closeEditor(force = false) {
    if (!force && isFormDirty && !window.confirm('当前表单还有未保存的修改，确定关闭吗？')) return;
    editorOpen = false;
    editingId = null;
    form = emptyForm();
    generatedPassword = '';
  }

  async function saveEntry() {
    clearError();
    if (!form.title.trim()) {
      setError('标题不能为空。');
      return;
    }
    busy = true;
    const wasEditing = Boolean(editingId);
    try {
      const saved = editingId ? await api.updateEntry(editingId, form) : await api.createEntry(form);
      closeEditor(true);
      await loadEntries();
      await selectEntry(saved.id);
      showToast(wasEditing ? '条目已更新' : '条目已保存');
    } catch (cause) {
      setError(cause);
    } finally {
      busy = false;
    }
  }

  async function deleteSelected() {
    if (!selectedEntry) return;
    if (!window.confirm('确定删除“' + selectedEntry.title + '”吗？删除后无法撤销。')) return;
    busy = true;
    clearError();
    try {
      await api.deleteEntry(selectedEntry.id);
      selectedId = null;
      selectedEntry = null;
      await loadEntries();
      showToast('条目已删除');
    } catch (cause) {
      setError(cause);
    } finally {
      busy = false;
    }
  }

  async function toggleFavorite(entry: EntrySummary | PasswordEntry) {
    try {
      await api.setFavorite(entry.id, !entry.favorite);
      if (selectedEntry?.id === entry.id) selectedEntry = { ...selectedEntry, favorite: !entry.favorite };
      await loadEntries();
      showToast(entry.favorite ? '已取消收藏' : '已加入收藏');
    } catch (cause) {
      setError(cause);
    }
  }

  async function copyValue(value: string, label: string) {
    if (!value) {
      showToast(label + '为空');
      return;
    }
    try {
      const result = await api.copySensitiveValue(value);
      showToast(label + '已复制，' + result.clearAfterSeconds + ' 秒后清理');
    } catch (cause) {
      setError(cause);
    }
  }

  function resetSensitiveUi() {
    entries = [];
    selectedId = null;
    selectedEntry = null;
    editorOpen = false;
    settingsOpen = false;
    generatorOpen = false;
    showDetailPassword = false;
  }

  async function lockNow() {
    try {
      await api.lockVault();
      resetSensitiveUi();
      await refreshStatus();
      mode = 'unlock';
      showToast('密码库已锁定');
    } catch (cause) {
      setError(cause);
    }
  }

  async function openSettings() {
    settingsDraft = { ...settings };
    settingsTab = 'safety';
    settingsOpen = true;
    clearError();
  }

  async function saveSettings() {
    busy = true;
    clearError();
    try {
      settings = await api.setSettings(settingsDraft);
      settingsDraft = { ...settings };
      settingsOpen = false;
      showToast('设置已保存');
    } catch (cause) {
      setError(cause);
    } finally {
      busy = false;
    }
  }

  async function backupVault() {
    busy = true;
    clearError();
    try {
      const filename = await api.createBackup();
      showToast('已创建加密备份 · ' + filename);
    } catch (cause) {
      setError(cause);
    } finally {
      busy = false;
    }
  }

  async function exportVault() {
    try {
      const destination = await save({
        defaultPath: appState?.vaultPathDisplayName ?? 'vault.pmvault',
        filters: [{ name: '加密密码库', extensions: ['pmvault'] }],
      });
      if (typeof destination !== 'string') return;
      busy = true;
      await api.exportVault(destination);
      showToast('加密密码库已导出');
    } catch (cause) {
      setError(cause, '导出失败，原密码库未受影响。');
    } finally {
      busy = false;
    }
  }

  async function changeMasterPassword() {
    clearError();
    if (!oldMasterPassword || !newMasterPassword) {
      setError('请输入旧主密码和新主密码。');
      return;
    }
    if (newMasterPassword !== newMasterConfirmation) {
      setError('两次输入的新主密码不一致。');
      return;
    }
    busy = true;
    try {
      await api.changeMasterPassword(oldMasterPassword, newMasterPassword);
      oldMasterPassword = '';
      newMasterPassword = '';
      newMasterConfirmation = '';
      showToast('主密码已更新');
    } catch (cause) {
      setError(cause);
    } finally {
      busy = false;
    }
  }

  async function generateForForm() {
    try {
      generatedPassword = await api.generatePassword(generatorOptions);
      generatorOpen = true;
    } catch (cause) {
      setError(cause);
    }
  }

  async function regeneratePassword() {
    try {
      generatedPassword = await api.generatePassword(generatorOptions);
    } catch (cause) {
      setError(cause);
    }
  }

  function useGeneratedPassword() {
    form.password = generatedPassword;
    generatorOpen = false;
    showFormPassword = true;
  }

  function signalActivity() {
    const now = Date.now();
    if (mode !== 'main' || now - lastActivitySignal < 12_000) return;
    lastActivitySignal = now;
    api.recordActivity().catch(() => undefined);
  }

  onMount(() => {
    bootstrap();
    statusTimer = setInterval(refreshStatus, 2_000);
    window.addEventListener('pointerdown', signalActivity, { passive: true });
    window.addEventListener('keydown', signalActivity);
  });

  onDestroy(() => {
    if (statusTimer) clearInterval(statusTimer);
    if (toastTimer) clearTimeout(toastTimer);
    window.removeEventListener('pointerdown', signalActivity);
    window.removeEventListener('keydown', signalActivity);
  });
</script>

{#if mode === 'loading'}
  <main class="loading-screen">
    <div class="loading-mark"><Icon name="shield" size={24} /></div>
    <p>正在准备本地密码库</p>
  </main>
{:else if mode === 'setup'}
  <main class="auth-shell">
    <section class="auth-brand-panel">
      <div class="brand-kicker"><span class="kicker-dot"></span> 离线优先 · Windows MVP</div>
      <div class="brand-hero">
        <div class="hero-emblem"><Icon name="shield" size={32} /></div>
        <h1>把钥匙<br /><em>留在自己手里。</em></h1>
        <p>Vaultroom 是一个只属于你的本地密码库。数据使用主密码在本机加密，不上传、不同步，也不需要账号。</p>
      </div>
      <div class="brand-footnote">
        <Icon name="lock" size={15} />
        <span>密码忘记后无法恢复，请选择你能长期记住的密码短语。</span>
      </div>
    </section>
    <section class="auth-form-panel">
      <div class="auth-card">
        <div class="auth-card-heading">
          <span class="eyebrow">第一次使用</span>
          <h2>创建你的本地密码库</h2>
          <p>先设置一个主密码。它不会被保存，也不会离开这台设备。</p>
        </div>
        <form on:submit|preventDefault={handleCreateVault} class="stack-form">
          <label class="field-label" for="setup-password">主密码</label>
          <div class="password-field">
            <input id="setup-password" bind:value={setupPassword} type={showSetupPassword ? 'text' : 'password'} placeholder="输入一个长密码短语" autocomplete="new-password" />
            <button type="button" class="input-action" aria-label={showSetupPassword ? '隐藏主密码' : '显示主密码'} on:click={() => (showSetupPassword = !showSetupPassword)}>
              <Icon name={showSetupPassword ? 'eye-off' : 'eye'} size={17} />
            </button>
          </div>
          <div class="strength-row">
            <div class="strength-bars" aria-hidden="true">
              {#each [1, 2, 3, 4, 5] as bar}
                <span class:filled={passwordStrength.score >= bar} class={passwordStrength.tone}></span>
              {/each}
            </div>
            <span class="strength-label {passwordStrength.tone}">{passwordStrength.label}</span>
          </div>
          <label class="field-label" for="setup-confirmation">再次输入</label>
          <div class="password-field">
            <input id="setup-confirmation" bind:value={setupConfirmation} type={showSetupPassword ? 'text' : 'password'} placeholder="再次确认主密码" autocomplete="new-password" />
          </div>
          {#if error}<div class="form-error"><Icon name="info" size={15} /> {error}</div>{/if}
          <button type="submit" class="primary-button full-button" disabled={busy}>
            {#if busy}<span class="spinner"></span> 正在创建…{:else}创建密码库 <Icon name="arrow-right" size={17} />{/if}
          </button>
        </form>
        <div class="auth-note"><Icon name="shield" size={15} /><span>默认保存在系统应用数据目录，磁盘内容始终是加密的。</span></div>
      </div>
    </section>
  </main>
{:else if mode === 'unlock'}
  <main class="auth-shell unlock-shell">
    <section class="auth-brand-panel">
      <div class="brand-kicker"><span class="kicker-dot"></span> Vaultroom · 本地密码库</div>
      <div class="brand-hero">
        <div class="hero-emblem"><Icon name="key" size={32} /></div>
        <h1>欢迎回来，<br /><em>你的秘密在这里。</em></h1>
        <p>解锁后才会在内存中读取条目。超过设置的空闲时间，密码库会自动锁定；你也可以随时手动锁定。</p>
      </div>
      <div class="brand-footnote">
        <Icon name="info" size={15} />
        <span>忘记主密码？没有恢复入口，也没有后门。请妥善保管主密码。</span>
      </div>
    </section>
    <section class="auth-form-panel">
      <div class="auth-card">
        <div class="auth-card-heading">
          <span class="eyebrow">密码库已锁定</span>
          <h2>输入主密码解锁</h2>
          <p>{selectedPath ? selectedPath.split(/[\\/]/).pop() : (appState?.vaultPathDisplayName ?? 'vault.pmvault')}</p>
        </div>
        <form on:submit|preventDefault={handleUnlock} class="stack-form">
          <label class="field-label" for="unlock-password">主密码</label>
          <div class="password-field">
            <input id="unlock-password" bind:value={unlockPassword} type={showUnlockPassword ? 'text' : 'password'} placeholder="输入主密码" autocomplete="current-password" />
            <button type="button" class="input-action" aria-label={showUnlockPassword ? '隐藏主密码' : '显示主密码'} on:click={() => (showUnlockPassword = !showUnlockPassword)}>
              <Icon name={showUnlockPassword ? 'eye-off' : 'eye'} size={17} />
            </button>
          </div>
          {#if error}<div class="form-error"><Icon name="info" size={15} /> {error}</div>{/if}
          <button type="submit" class="primary-button full-button" disabled={busy}>
            {#if busy}<span class="spinner"></span> 正在解锁…{:else}<Icon name="unlock" size={17} /> 解锁密码库{/if}
          </button>
        </form>
        <div class="auth-secondary-actions">
          <button type="button" class="quiet-button" on:click={chooseVault}><Icon name="external" size={16} /> 打开其他密码库</button>
          {#if selectedPath || (appState?.vaultPathDisplayName && appState.vaultPathDisplayName !== 'vault.pmvault')}<button type="button" class="text-button" on:click={returnToDefaultVault}>返回默认库</button>{/if}
        </div>
        <div class="auth-note"><Icon name="shield" size={15} /><span>错误的主密码不会告诉你更多细节，防止泄露密码库信息。</span></div>
      </div>
    </section>
  </main>
{:else}
  <div class="app-shell">
    <aside class="sidebar">
      <div class="sidebar-top">
        <div class="brand-lockup">
          <div class="logo-mark">V</div>
          <div><strong>Vaultroom</strong><span>离线密码库</span></div>
        </div>
        <div class="vault-chip"><span class="status-dot"></span><span class="truncate">{appState?.vaultPathDisplayName ?? 'vault.pmvault'}</span><Icon name="lock" size={13} /></div>
      </div>

      <nav class="sidebar-nav" aria-label="密码库导航">
        <span class="nav-section-label">浏览</span>
        <button class:active={view === 'all' && !activeTag} class="nav-item" on:click={() => { view = 'all'; activeTag = null; loadEntries(); }}>
          <Icon name="key" size={17} /><span>全部条目</span><b>{entries.length}</b>
        </button>
        <button class:active={view === 'favorites'} class="nav-item" on:click={() => { view = 'favorites'; activeTag = null; loadEntries(); }}>
          <Icon name="star" size={17} /><span>收藏</span><b>{entries.filter((entry) => entry.favorite).length}</b>
        </button>
        <button class:active={view === 'recent'} class="nav-item" on:click={() => { view = 'recent'; activeTag = null; loadEntries(); }}>
          <Icon name="refresh" size={17} /><span>最近修改</span>
        </button>
        {#if allTags.length}
          <span class="nav-section-label tags-label">标签</span>
          {#each allTags.slice(0, 6) as tag}
            <button class:active={activeTag === tag} class="nav-item tag-item" on:click={() => { activeTag = tag; view = 'all'; loadEntries(); }}>
              <span class="tag-swatch"></span><span class="truncate">{tag}</span>
            </button>
          {/each}
        {/if}
      </nav>

      <div class="sidebar-bottom">
        <div class="privacy-callout"><Icon name="shield" size={17} /><div><strong>只在本机</strong><span>数据不会上传到网络</span></div></div>
        <button class:active={view === 'settings'} class="nav-item" on:click={() => { view = 'settings'; openSettings(); }}><Icon name="settings" size={17} /><span>设置</span></button>
        <button class="nav-item lock-nav-item" on:click={lockNow}><Icon name="lock" size={17} /><span>立即锁定</span><kbd>⌘L</kbd></button>
      </div>
    </aside>

    <main class="workspace">
      <header class="workspace-header">
        <div class="page-title-group">
          <span class="section-kicker">{view === 'favorites' ? '收藏夹' : view === 'recent' ? '活动记录' : '你的密码库'}</span>
          <h1>{view === 'favorites' ? '收藏条目' : view === 'recent' ? '最近修改' : activeTag ? '#' + activeTag : '全部条目'}</h1>
        </div>
        <div class="header-actions">
          <div class="auto-lock-indicator"><span class="pulse-dot"></span>{formatRemaining(autoLockRemaining ?? appState?.autoLockSecondsRemaining ?? null)}</div>
          <button class="icon-button" title="设置" aria-label="设置" on:click={openSettings}><Icon name="settings" size={18} /></button>
          <button class="lock-button" on:click={lockNow}><Icon name="lock" size={15} /> 锁定</button>
        </div>
      </header>

      <section class="toolbar">
        <div class="search-box">
          <Icon name="search" size={18} />
          <input bind:value={searchQuery} on:input={loadEntries} placeholder="搜索标题、用户名、网址或标签" aria-label="搜索密码条目" />
          {#if searchQuery}<button class="clear-search" aria-label="清除搜索" on:click={() => { searchQuery = ''; loadEntries(); }}><Icon name="close" size={14} /></button>{/if}
        </div>
        <div class="toolbar-actions">
          <label class="sort-select"><span>排序</span><select bind:value={sortMode} on:change={loadEntries}><option value="updated_desc">最近修改</option><option value="title_asc">标题 A–Z</option><option value="title_desc">标题 Z–A</option></select><Icon name="chevron-down" size={14} /></label>
          <button class="primary-button add-button" on:click={openNewEntry}><Icon name="plus" size={17} /> 新建条目</button>
        </div>
      </section>

      <section class="content-grid">
        <div class="entries-panel">
          <div class="panel-caption"><span>{entries.length} 条记录</span><span class="caption-rule"></span><span class="caption-muted">敏感字段按需读取</span></div>
          {#if entries.length === 0}
            <div class="empty-state">
              <div class="empty-icon"><Icon name="key" size={23} /></div>
              <h2>{searchQuery || activeTag || view === 'favorites' ? '没有找到匹配条目' : '密码库还是空的'}</h2>
              <p>{searchQuery || activeTag || view === 'favorites' ? '换个关键词或筛选条件试试。' : '从第一条记录开始，把日常登录信息放在一个安全的地方。'}</p>
              {#if !searchQuery && !activeTag && view !== 'favorites'}<button class="secondary-button" on:click={openNewEntry}><Icon name="plus" size={16} /> 创建第一条记录</button>{/if}
            </div>
          {:else}
            <div class="entry-list">
              {#each entries as entry (entry.id)}
                <button class:selected={selectedId === entry.id} class="entry-row" on:click={() => selectEntry(entry.id)}>
                  <span class="entry-avatar">{displayInitials(entry)}</span>
                  <span class="entry-row-main"><strong>{entry.title}</strong><span>{entry.username || domainFromUrl(entry.url) || '没有用户名'}</span></span>
                  {#if entry.favorite}<span class="row-star"><Icon name="star" size={14} /></span>{/if}
                  <span class="entry-row-date">{formatDate(entry.updatedAt)}</span>
                </button>
              {/each}
            </div>
          {/if}
        </div>

        <div class="detail-panel">
          {#if detailBusy}
            <div class="detail-loading"><span class="spinner dark"></span><span>正在读取条目…</span></div>
          {:else if selectedEntry}
            <div class="detail-heading">
              <div class="detail-title-wrap"><span class="detail-avatar">{displayInitials(selectedEntry)}</span><div><div class="detail-eyebrow">密码条目</div><h2>{selectedEntry.title}</h2>{#if selectedEntry.url}<a href={selectedEntry.url.includes('://') ? selectedEntry.url : 'https://' + selectedEntry.url} target="_blank" rel="noreferrer">{domainFromUrl(selectedEntry.url)} <Icon name="external" size={12} /></a>{/if}</div></div>
              <div class="detail-actions"><button class:favorite-active={selectedEntry.favorite} class="icon-button subtle" title={selectedEntry.favorite ? '取消收藏' : '加入收藏'} aria-label={selectedEntry.favorite ? '取消收藏' : '加入收藏'} on:click={() => toggleFavorite(selectedEntry)}><Icon name="star" size={18} /></button><button class="icon-button subtle" title="编辑" aria-label="编辑" on:click={openEditEntry}><Icon name="edit" size={17} /></button><button class="icon-button subtle danger" title="删除" aria-label="删除" on:click={deleteSelected}><Icon name="trash" size={17} /></button></div>
            </div>
            <div class="detail-divider"></div>
            <div class="secret-list">
              <div class="secret-row"><div class="secret-label">用户名<span>LOGIN</span></div><div class="secret-value"><code>{selectedEntry.username || '—'}</code><button class="copy-button" on:click={() => copyValue(selectedEntry?.username ?? '', '用户名')}><Icon name="copy" size={15} /> 复制</button></div></div>
              <div class="secret-row"><div class="secret-label">密码<span>PASSWORD</span></div><div class="secret-value"><code class:revealed={showDetailPassword}>{showDetailPassword ? selectedEntry.password || '—' : '••••••••••••'}</code><button class="copy-button" on:click={() => (showDetailPassword = !showDetailPassword)}><Icon name={showDetailPassword ? 'eye-off' : 'eye'} size={15} /> {showDetailPassword ? '隐藏' : '显示'}</button><button class="copy-button filled" on:click={() => copyValue(selectedEntry?.password ?? '', '密码')}><Icon name="copy" size={15} /> 复制</button></div></div>
            </div>
            <div class="detail-section"><div class="detail-section-title">备注</div><p class:muted={!selectedEntry.notes}>{selectedEntry.notes || '还没有添加备注。'}</p></div>
            {#if selectedEntry.tags.length}<div class="detail-section"><div class="detail-section-title">标签</div><div class="tag-list">{#each selectedEntry.tags as tag}<button class="tag-pill" on:click={() => { activeTag = tag; view = 'all'; loadEntries(); }}>#{tag}</button>{/each}</div></div>{/if}
            <div class="detail-footer"><span>创建于 {formatDate(selectedEntry.createdAt)}</span><span>最后修改 {formatDate(selectedEntry.updatedAt)}</span></div>
          {:else}
            <div class="detail-empty"><div class="detail-empty-mark"><Icon name="shield" size={28} /></div><h2>选中一个条目</h2><p>列表只展示非敏感信息。打开后，密码字段才会按需进入内存。</p><button class="secondary-button" on:click={openNewEntry}><Icon name="plus" size={16} /> 新建条目</button></div>
          {/if}
        </div>
      </section>
    </main>
  </div>
{/if}

{#if editorOpen}
  <div class="modal-backdrop" role="presentation" on:click={(event) => event.target === event.currentTarget && closeEditor()}>
    <div class="modal-card editor-modal" role="dialog" aria-modal="true" aria-labelledby="editor-title">
      <header class="modal-header"><div><span class="eyebrow">{editingId ? '编辑条目' : '新建条目'}</span><h2 id="editor-title">{editingId ? '更新密码信息' : '添加一条新记录'}</h2></div><button class="icon-button" aria-label="关闭" on:click={() => closeEditor()}><Icon name="close" size={19} /></button></header>
      <form class="editor-form" on:submit|preventDefault={saveEntry}>
        <div class="form-grid two-columns">
          <div class="form-control full-span"><label for="entry-title">标题 <span>必填</span></label><input id="entry-title" bind:value={form.title} placeholder="例如：个人邮箱、GitHub" /></div>
          <div class="form-control"><label for="entry-username">用户名</label><input id="entry-username" bind:value={form.username} placeholder="name@example.com" autocomplete="off" /></div>
          <div class="form-control"><label for="entry-url">网址</label><input id="entry-url" bind:value={form.url} placeholder="https://example.com" inputmode="url" /></div>
          <div class="form-control full-span"><label for="entry-password">密码</label><div class="input-with-actions"><input id="entry-password" bind:value={form.password} type={showFormPassword ? 'text' : 'password'} placeholder="输入密码或使用生成器" autocomplete="new-password" /><button type="button" class="input-action" aria-label={showFormPassword ? '隐藏密码' : '显示密码'} on:click={() => (showFormPassword = !showFormPassword)}><Icon name={showFormPassword ? 'eye-off' : 'eye'} size={16} /></button><button type="button" class="generator-trigger" on:click={generateForForm}><Icon name="spark" size={15} /> 生成</button></div></div>
          <div class="form-control full-span"><label for="entry-notes">备注</label><textarea id="entry-notes" bind:value={form.notes} rows="4" placeholder="记录恢复码、使用说明或其他提醒…"></textarea></div>
          <div class="form-control full-span"><label for="entry-tags">标签 <span>用逗号分隔</span></label><input id="entry-tags" value={form.tags.join(', ')} on:input={(event) => { form.tags = (event.currentTarget as HTMLInputElement).value.split(',').map((tag) => tag.trim()).filter(Boolean); }} placeholder="工作，个人，开发" /></div>
        </div>
        <div class="form-footer-row"><label class="switch-label"><input type="checkbox" bind:checked={form.favorite} /><span class="switch"></span><span>加入收藏</span></label><div class="modal-actions"><button type="button" class="secondary-button" on:click={() => closeEditor()}>取消</button><button type="submit" class="primary-button" disabled={busy}>{#if busy}<span class="spinner"></span> 保存中…{:else}<Icon name="check" size={16} /> 保存条目{/if}</button></div></div>
      </form>
    </div>
  </div>
{/if}

{#if generatorOpen}
  <div class="modal-backdrop top-layer" role="presentation" on:click={(event) => event.target === event.currentTarget && (generatorOpen = false)}>
    <div class="modal-card generator-modal" role="dialog" aria-modal="true" aria-labelledby="generator-title">
      <header class="modal-header"><div><span class="eyebrow">安全随机数</span><h2 id="generator-title">密码生成器</h2></div><button class="icon-button" aria-label="关闭" on:click={() => (generatorOpen = false)}><Icon name="close" size={19} /></button></header>
      <div class="generated-preview"><code>{generatedPassword || '点击重新生成'}</code><button class="icon-button" aria-label="复制生成的密码" on:click={() => copyValue(generatedPassword, '生成的密码')}><Icon name="copy" size={17} /></button></div>
      <div class="generator-controls"><label class="range-label"><span>长度 <b>{generatorOptions.length}</b></span><input type="range" min="8" max="64" bind:value={generatorOptions.length} /></label><div class="generator-checks"><label><input type="checkbox" bind:checked={generatorOptions.includeUppercase} /> 大写字母</label><label><input type="checkbox" bind:checked={generatorOptions.includeLowercase} /> 小写字母</label><label><input type="checkbox" bind:checked={generatorOptions.includeNumbers} /> 数字</label><label><input type="checkbox" bind:checked={generatorOptions.includeSymbols} /> 特殊字符</label><label><input type="checkbox" bind:checked={generatorOptions.excludeAmbiguous} /> 排除易混淆字符</label></div></div>
      <div class="modal-actions"><button class="secondary-button" on:click={regeneratePassword}><Icon name="refresh" size={16} /> 重新生成</button><button class="primary-button" on:click={useGeneratedPassword}><Icon name="check" size={16} /> 使用这个密码</button></div>
      <div class="generator-note"><Icon name="shield" size={15} /> 使用操作系统安全随机数生成，密码不会写入日志。</div>
    </div>
  </div>
{/if}

{#if settingsOpen}
  <div class="modal-backdrop" role="presentation" on:click={(event) => event.target === event.currentTarget && (settingsOpen = false)}>
    <div class="modal-card settings-modal" role="dialog" aria-modal="true" aria-labelledby="settings-title">
      <header class="modal-header"><div><span class="eyebrow">偏好设置</span><h2 id="settings-title">让 Vaultroom 按你的节奏工作</h2></div><button class="icon-button" aria-label="关闭" on:click={() => (settingsOpen = false)}><Icon name="close" size={19} /></button></header>
      <div class="settings-tabs"><button class:active={settingsTab === 'safety'} on:click={() => (settingsTab = 'safety')}>安全与清理</button><button class:active={settingsTab === 'account'} on:click={() => (settingsTab = 'account')}>主密码</button></div>
      {#if settingsTab === 'safety'}
        <div class="settings-section"><div class="setting-row"><div><strong>空闲自动锁定</strong><p>应用无操作时自动清理内存中的解密数据。</p></div><select bind:value={settingsDraft.autoLockSeconds}><option value={300}>5 分钟</option><option value={900}>15 分钟（默认）</option><option value={1800}>30 分钟</option><option value={0}>关闭</option></select></div><div class="setting-row"><div><strong>剪贴板清理</strong><p>复制用户名或密码后，多久尝试清除剪贴板。</p></div><select bind:value={settingsDraft.clipboardClearSeconds}><option value={15}>15 秒</option><option value={30}>30 秒（默认）</option><option value={60}>60 秒</option><option value={120}>2 分钟</option></select></div><div class="settings-divider"></div><div class="setting-row action-row"><div><strong>创建加密备份</strong><p>保留最近三份加密备份，不生成明文副本。</p></div><button class="secondary-button" on:click={backupVault} disabled={busy}><Icon name="shield" size={16} /> 立即备份</button></div><div class="setting-row action-row"><div><strong>导出加密密码库</strong><p>把当前加密文件复制到你选择的位置。</p></div><button class="secondary-button" on:click={exportVault} disabled={busy}><Icon name="external" size={16} /> 导出文件</button></div></div>
      {:else}
        <div class="settings-section password-settings"><div class="settings-security-note"><Icon name="key" size={19} /><div><strong>主密码只用于解锁密钥</strong><p>修改主密码时只重新包装数据密钥，不会把条目变成明文。</p></div></div><div class="form-control"><label for="old-master">旧主密码</label><input id="old-master" bind:value={oldMasterPassword} type="password" autocomplete="current-password" /></div><div class="form-control"><label for="new-master">新主密码</label><input id="new-master" bind:value={newMasterPassword} type="password" autocomplete="new-password" /></div><div class="form-control"><label for="new-master-confirm">再次输入新主密码</label><input id="new-master-confirm" bind:value={newMasterConfirmation} type="password" autocomplete="new-password" /></div><button class="secondary-button change-password-button" on:click={changeMasterPassword} disabled={busy}><Icon name="refresh" size={16} /> 更新主密码</button></div>
      {/if}
      {#if error}<div class="form-error settings-error"><Icon name="info" size={15} /> {error}</div>{/if}
      <footer class="settings-footer"><span>Vaultroom v{appState?.appVersion ?? '0.1.0'} · 当前文件 {appState?.vaultPathDisplayName ?? 'vault.pmvault'}</span>{#if settingsTab === 'safety'}<button class="primary-button" on:click={saveSettings} disabled={busy}>保存设置</button>{/if}</footer>
    </div>
  </div>
{/if}

{#if toast}<div class="toast" role="status"><span class="toast-icon"><Icon name="check" size={14} /></span>{toast}</div>{/if}
