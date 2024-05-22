import React from "react";
import { BrowserRouter, Routes, Route } from "react-router-dom";

import NotesPage from "./pages/NotesPage";
import TodoPage from "./pages/TodoPage";
import Settings from "./pages/Settings";
import NotesDetail from "./pages/NotesDetail";
import SignIn from "./pages/SignIn";
import SignUp from "./pages/SignUp";
import PrivateRoutes from "./components/PrivateRoutes";
import { useSelector } from "react-redux";
const App = () => {
  const user = useSelector((state) => state.user);
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<SignUp />} />
        <Route path="/sign-in" element={<SignIn />} />
        <Route element={<PrivateRoutes />}>
          <Route path="/notes-page" element={<NotesPage />} />
          <Route path="/todo" element={<TodoPage />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="/notes-details" element={<NotesDetail />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
};

export default App;