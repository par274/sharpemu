import type { GameEntry } from './types'

function cover(title: string, from: string, to: string, motif: string): string {
  const safeTitle = title.replaceAll('&', '&amp;')
  const svg = `
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 720 960">
      <defs>
        <linearGradient id="g" x1="0" y1="0" x2="1" y2="1">
          <stop stop-color="${from}"/>
          <stop offset="1" stop-color="${to}"/>
        </linearGradient>
        <filter id="b"><feGaussianBlur stdDeviation="32"/></filter>
      </defs>
      <rect width="720" height="960" fill="url(#g)"/>
      <circle cx="570" cy="210" r="250" fill="white" opacity=".12" filter="url(#b)"/>
      <path d="${motif}" fill="none" stroke="white" stroke-width="10" opacity=".18"/>
      <path d="M0 680Q220 570 380 720T720 650V960H0Z" fill="#030712" opacity=".52"/>
      <text x="58" y="790" fill="white" font-family="Segoe UI,Arial" font-size="58" font-weight="700">${safeTitle}</text>
      <text x="60" y="850" fill="white" opacity=".58" font-family="Segoe UI,Arial" font-size="19" letter-spacing="7">SHARPEMU</text>
    </svg>`
  return `data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg)}`
}

function backdrop(title: string, from: string, to: string): string {
  const safeTitle = title.replaceAll('&', '&amp;')
  const svg = `
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1920 1080">
      <defs>
        <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">
          <stop stop-color="${from}"/>
          <stop offset="1" stop-color="${to}"/>
        </linearGradient>
      </defs>
      <rect width="1920" height="1080" fill="url(#bg)"/>
      <circle cx="1380" cy="280" r="440" fill="white" opacity=".1"/>
      <path d="M0 850Q420 520 830 820T1560 650Q1770 590 1920 720V1080H0Z" fill="#030712" opacity=".5"/>
      <path d="M220 730Q610 180 980 650T1740 300" fill="none" stroke="white" stroke-width="18" opacity=".13"/>
      <text x="1220" y="830" fill="white" opacity=".3" font-family="Google Sans,Segoe UI,Arial" font-size="112" font-weight="700">${safeTitle}</text>
    </svg>`
  return `data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg)}`
}

export function installDemoState(): void {
  const games: GameEntry[] = [
    {
      ebootPath: 'demo://echoes',
      name: 'Echoes of Aster',
      titleId: 'CUSA 49211',
      version: '01.14',
      sizeText: '58.7 GB',
      coverDataUri: cover('ECHOES', '#0d6a80', '#09121e', 'M-40 470Q210 170 410 430T800 260'),
      hasBackground: true,
      lastPlayedText: 'Played 2 hours ago',
      hasPlayed: true,
    },
    {
      ebootPath: 'demo://redshift',
      name: 'Redshift Protocol',
      titleId: 'CUSA 10842',
      version: '02.01',
      sizeText: '42.3 GB',
      coverDataUri: cover('REDSHIFT', '#c33f34', '#220a12', 'M80 110 640 820M-20 330 520 940M300-20 740 480'),
      lastPlayedText: 'Played yesterday',
      hasPlayed: true,
    },
    {
      ebootPath: 'demo://north',
      name: 'Northbound',
      titleId: 'CUSA 77104',
      version: '01.06',
      sizeText: '27.9 GB',
      coverDataUri: cover('NORTHBOUND', '#7295b3', '#142130', 'M20 650 210 280 340 590 480 190 710 690'),
      lastPlayedText: null,
      hasPlayed: false,
    },
    {
      ebootPath: 'demo://neon',
      name: 'Neon Circuit',
      titleId: 'CUSA 36190',
      version: '01.22',
      sizeText: '19.4 GB',
      coverDataUri: cover('NEON', '#8a2be2', '#07155e', 'M30 500Q190 120 350 500T690 500M20 600Q190 220 350 600T700 600'),
      lastPlayedText: 'Played last week',
      hasPlayed: true,
    },
    {
      ebootPath: 'demo://veil',
      name: 'Beyond the Veil',
      titleId: 'CUSA 65418',
      version: '01.00',
      sizeText: '73.1 GB',
      coverDataUri: cover('THE VEIL', '#88735a', '#101014', 'M360 80C180 260 180 620 360 860 540 620 540 260 360 80Z'),
      lastPlayedText: null,
      hasPlayed: false,
    },
  ]

  const receive = (globalThis as any).__sharpemu?.receive
  receive?.('localization', {
    code: 'en',
    strings: {
      'Page.Library': 'Games',
      'Page.Options': 'System',
      'Page.GameCount.One': '1 game',
      'Page.GameCount.Other': '{0} games',
      'Library.SearchWatermark': 'Search games',
      'Library.AddFolder': '＋ Add folder',
      'Library.Rescan': '⟳ Rescan',
      'Library.OpenFile': 'Open file…',
      'Library.Row.AllGames': 'Your games',
      'Library.Hero.Resume': 'Resume',
      'Library.Context.Launch': 'Play',
      'Library.Context.GameSettings': 'Game settings',
      'Library.Context.OpenFolder': 'Open game folder',
      'Library.Context.CopyPath': 'Copy path',
      'Library.Context.Remove': 'Remove from library',
      'Console.Title': 'Console',
    },
  })
  receive?.('library', { games })
  receive?.('recent', { games: games.slice(0, 2), lastPlayed: games[0] })
  receive?.('background', {
    ebootPath: games[0]!.ebootPath,
    backgroundDataUri: backdrop('ECHOES OF ASTER', '#0a7183', '#07111d'),
  })
}
