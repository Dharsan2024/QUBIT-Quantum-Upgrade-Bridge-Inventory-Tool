import { createBrowserRouter } from 'react-router';
import { Layout } from './components/Layout';
import { Projects } from './pages/Projects';
import { Inventory } from './pages/Inventory';
import { Risk } from './pages/Risk';
import { Timeline } from './pages/Timeline';
import { Migrations } from './pages/Migrations';
import { MigrationDetail } from './pages/MigrationDetail';
import { Scans } from './pages/Scans';
import { Cbom } from './pages/Cbom';
import { Settings } from './pages/Settings';
import { Login } from './pages/Login';

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
        element: <Settings />,
      },
      // In a real implementation these would be nested under /p/:pid
      {
        path: 'inventory',
        element: <Inventory />,
      },
      {
        path: 'p/:pid/inventory',
        element: <Inventory />,
      },
      {
        path: 'risk',
        element: <Risk />,
      },
      {
        path: 'p/:pid/risk',
        element: <Risk />,
      },
      {
        path: 'timeline',
        element: <Timeline />,
      },
      {
        path: 'p/:pid/timeline',
        element: <Timeline />,
      },
      {
        path: 'migrations',
        element: <Migrations />,
      },
      {
        path: 'p/:pid/migrations',
        element: <Migrations />,
      },
      {
        path: 'm/:mid',
        element: <MigrationDetail />,
      },
      {
        path: 'scans',
        element: <Scans />,
      },
      {
        path: 'p/:pid/scans',
        element: <Scans />,
      },
      {
        path: 'cbom',
        element: <Cbom />,
      },
      {
        path: 'p/:pid/cbom',
        element: <Cbom />,
      },
    ],
  },
]);
