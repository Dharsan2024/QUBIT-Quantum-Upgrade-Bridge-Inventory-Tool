import { createBrowserRouter } from 'react-router';
import { Layout } from './components/Layout';
import { LazyChartPage } from './components/LazyChartPage';
import { Projects } from './pages/Projects';
import { Inventory } from './pages/Inventory';
import { Migrations } from './pages/Migrations';
import { Scans } from './pages/Scans';
import { Cbom } from './pages/Cbom';
import { Compliance } from './pages/Compliance';
import { Report } from './pages/Report';
import { Settings } from './pages/Settings';
import { Login } from './pages/Login';
import { Risk, Timeline } from './pages/lazy';

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
        element: (
          <LazyChartPage>
            <Risk />
          </LazyChartPage>
        ),
      },
      {
        path: 'p/:pid/risk',
        element: (
          <LazyChartPage>
            <Risk />
          </LazyChartPage>
        ),
      },
      {
        path: 'timeline',
        element: (
          <LazyChartPage>
            <Timeline />
          </LazyChartPage>
        ),
      },
      {
        path: 'p/:pid/timeline',
        element: (
          <LazyChartPage>
            <Timeline />
          </LazyChartPage>
        ),
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
        path: 'scans',
        element: <Scans />,
      },
      {
        path: 'p/:pid/scans',
        element: <Scans />,
      },
      {
        path: 'compliance',
        element: <Compliance />,
      },
      {
        path: 'p/:pid/compliance',
        element: <Compliance />,
      },
      {
        path: 'cbom',
        element: <Cbom />,
      },
      {
        path: 'p/:pid/cbom',
        element: <Cbom />,
      },
      {
        path: 'report/:scanId',
        element: <Report />,
      },
    ],
  },
]);
