
import { createBrowserRouter, Outlet, Link } from "react-router";
import { Inventory } from "./pages/Inventory";
import { Shield } from "lucide-react";

function RootLayout() {
  return (
    <div className="min-h-screen bg-gray-50 flex flex-col">
      <nav className="bg-indigo-700 text-white shadow-md">
        <div className="max-w-7xl mx-auto px-4 h-16 flex items-center gap-8">
          <div className="flex items-center gap-2 font-bold text-xl tracking-wide">
            <Shield className="w-6 h-6 text-indigo-300" />
            QUBIT
          </div>
          <div className="flex items-center gap-4 text-sm font-medium">
            <Link to="/" className="hover:text-indigo-200 transition-colors">Inventory</Link>
            {/* Other pages would go here */}
          </div>
        </div>
      </nav>
      <div className="flex-1 bg-gray-50">
        <Outlet />
      </div>
    </div>
  );
}

export const router = createBrowserRouter([
  {
    path: "/",
    element: <RootLayout />,
    children: [
      {
        path: "/",
        element: <Inventory />,
      },
    ],
  },
]);
