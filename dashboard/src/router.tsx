import { createBrowserRouter } from 'react-router';
import { Layout } from './components/Layout';
import { LazyPage } from './components/LazyPage';
import { Projects } from './pages/Projects';
import { Login } from './pages/Login';
import {
  Cbom,
  Compliance,
  Inventory,
  Migrations,
  Report,
  Risk,
  Scans,
  Settings,
  Timeline,
} from './pages/lazy';

export const router = createBrowserRouter([
  {
    path: '/login',
    element: <Login />,
  },
  {
    path: '/',
    element: <Layout />,
    children: [
      {
        index: true,
        element: <Projects />,
      },
      {
        path: 'settings',
        element: (
          <LazyPage>
            <Settings />
          </LazyPage>
        ),
      },
      // In a real implementation these would be nested under /p/:pid
      {
        path: 'inventory',
        element: (
          <LazyPage>
            <Inventory />
          </LazyPage>
        ),
      },
      {
        path: 'p/:pid/inventory',
        element: (
          <LazyPage>
            <Inventory />
          </LazyPage>
        ),
      },
      {
        path: 'risk',
        element: (
          <LazyPage>
            <Risk />
          </LazyPage>
        ),
      },
      {
        path: 'p/:pid/risk',
        element: (
          <LazyPage>
            <Risk />
          </LazyPage>
        ),
      },
      {
        path: 'timeline',
        element: (
          <LazyPage>
            <Timeline />
          </LazyPage>
        ),
      },
      {
        path: 'p/:pid/timeline',
        element: (
          <LazyPage>
            <Timeline />
          </LazyPage>
        ),
      },
      {
        path: 'migrations',
        element: (
          <LazyPage>
            <Migrations />
          </LazyPage>
        ),
      },
      {
        path: 'p/:pid/migrations',
        element: (
          <LazyPage>
            <Migrations />
          </LazyPage>
        ),
      },
      {
        path: 'scans',
        element: (
          <LazyPage>
            <Scans />
          </LazyPage>
        ),
      },
      {
        path: 'p/:pid/scans',
        element: (
          <LazyPage>
            <Scans />
          </LazyPage>
        ),
      },
      {
        path: 'compliance',
        element: (
          <LazyPage>
            <Compliance />
          </LazyPage>
        ),
      },
      {
        path: 'p/:pid/compliance',
        element: (
          <LazyPage>
            <Compliance />
          </LazyPage>
        ),
      },
      {
        path: 'cbom',
        element: (
          <LazyPage>
            <Cbom />
          </LazyPage>
        ),
      },
      {
        path: 'p/:pid/cbom',
        element: (
          <LazyPage>
            <Cbom />
          </LazyPage>
        ),
      },
      {
        path: 'report/:scanId',
        element: (
          <LazyPage>
            <Report />
          </LazyPage>
        ),
      },
    ],
  },
]);
