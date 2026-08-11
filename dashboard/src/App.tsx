import { RouterProvider } from 'react-router';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { router } from './router';
import { BootGate } from './components/BootGate';

// Resilient defaults: transient failures during the engine's first seconds self-heal instead of
// surfacing an error toast. The BootGate already ensures the API is up before we render, but a
// couple of retries with backoff keeps any race quiet.
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 3,
      retryDelay: (n) => Math.min(400 * 2 ** n, 2000),
      staleTime: 10_000,
      refetchOnWindowFocus: false,
    },
  },
});

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BootGate>
        <RouterProvider router={router} />
      </BootGate>
    </QueryClientProvider>
  );
}

export default App;
