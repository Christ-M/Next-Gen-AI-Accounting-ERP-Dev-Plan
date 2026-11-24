'use client';

/**
 * Status footer — pinned to the bottom edge of the app shell (mt-auto).
 * Mirrors the "platform status bar" from the design system: status, version,
 * encryption & real-time indicators.
 */
import { Activity, Lock, Sparkles } from 'lucide-react';
import { useI18n } from '@/lib/i18n';
import { APP } from '@/core/config/app.config';
import { useAppStore } from '@/lib/stores/app-store';
import { LanguageToggle } from '@/components/common/controls';
import { cn } from '@/lib/utils';

export function StatusFooter() {
  const { t } = useI18n();
  const { view } = useAppStore();

  // Small contextual Easter egg: the status strip reflects the active phase.
  // Phase 24 — the set now mirrors app-shell LIVE_MODULE_KEYS (the phases ≤7
  // legacy list answered "Coming soon" for every live post-16 module).
  const LIVE_MODULES = new Set([
    'module:accounting', 'module:inventory', 'module:sales',
    'module:checks', 'module:calendar', 'module:reports', 'module:ai',
    'module:assets', 'module:payroll', 'module:hr', 'module:costcenters',
    'module:documents', 'module:approvals', 'module:manufacturing',
  ]);
  const phaseHint = view.startsWith('module:') && !LIVE_MODULES.has(view)
    ? t('common.comingSoon')
    : t('footer.phase');

  return (
    <footer className="mt-auto border-t border-border/70 bg-sidebar/60 backdrop-blur-md">
      <div className="mx-auto flex max-w-[1500px] flex-wrap items-center gap-x-6 gap-y-2 px-4 py-2.5 text-[11px] text-muted-foreground md:px-6">
        {/* Status */}
        <span className="flex items-center gap-2">
          <span className="relative flex size-2" aria-hidden>
            <span className="absolute inline-flex size-full animate-ping rounded-full bg-neon-green opacity-60" />
            <span className="relative inline-flex size-2 rounded-full bg-neon-green shadow-[0_0_8px_var(--neon-green)]" />
          </span>
          <span className="font-semibold">{t('footer.allSystems')}</span>
        </span>

        {/* Version / phase */}
        <span className="hidden items-center gap-2 sm:flex">
          <span className="rounded-md border border-border/70 px-1.5 py-0.5 font-mono text-[10px]">
            v{APP.version}
          </span>
          {phaseHint}
        </span>

        <span className="ms-auto flex items-center gap-5">
          <span className="hidden items-center gap-1.5 md:flex">
            <Lock className="size-3 text-neon-green" aria-hidden />
            {t('footer.encrypted')}
          </span>
          <span className="hidden items-center gap-1.5 md:flex">
            <Activity className="size-3 text-neon-cyan" aria-hidden />
            {t('footer.realTime')}
          </span>
          <span className={cn('hidden items-center gap-1.5 lg:flex')}>
            <Sparkles className="size-3 text-neon-purple" aria-hidden />
            {t('footer.aiEngine')}
          </span>
          <LanguageToggle compact />
        </span>
      </div>
    </footer>
  );
}
