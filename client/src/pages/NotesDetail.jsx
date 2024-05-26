import React, { useState, useEffect } from "react";
import ReactQuill from "react-quill";
import "react-quill/dist/quill.snow.css";
import { useSelector } from "react-redux";
import { useNavigate } from "react-router-dom";
import { FaArrowAltCircleLeft } from "react-icons/fa";

const AddNotePopUp = () => {
  const navigate = useNavigate();
  const user = useSelector((state) => state.user.payload);
  const noteId = useSelector((state) => state.editNotes);

  const [title, setTitle] = useState("");
  const [notesDescription, setNotesDescription] = useState("");
  const [loading, setLoading] = useState(false);
  const [loading2, setLoading2] = useState(false);
  const [err, setErr] = useState();
  const [deletePopUp, setDeletePopUp] = useState(false);

  const getNote = async () => {
    const res = await fetch(`/api/notes/get-specific-note/${noteId.payload}`, {
      method: "GET",
      headers: {
        "Content-Type": "application/json",
      },
    });
    const data = await res.json();

    if (res.ok) {
      setNotesDescription(data.notesData.notesDescription);
      setTitle(data.notesData.title);
    }
    if (!res.ok) {
      setLoading(false);
      setErr(data.message);
    }
  };
  const updateNotes = async () => {
    try {
      const formData = {
        title,
        notesDescription,
      };

      setLoading(true);
      const res = await fetch(`/api/notes/edit-note/${noteId.payload}`, {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(formData),
      });
      const data = await res.json();
      if (res.ok) {
        setLoading(false);
        setErr(data.message);
        setTimeout(() => {
          navigate("/notes-page");
        }, 1000);
      }
      if (!res.ok) {
        setLoading(false);
        setErr(data.message);
      }
    } catch (error) {
      setLoading(false);
      setErr(data.message);
    }
  };

  const deleteNotes = async () => {
    try {
      setLoading2(true);
      const res = await fetch(`/api/notes/delete-note/${noteId.payload}`, {
        method: "DELETE",
      });
      const data = await res.json();
      if (!res.ok) {
        setErr(data.message);
        setLoading2(false);
        return;
      }
      if (res.ok) {
        setErr(data.message);
        setLoading2(false);
        setDeletePopUp(false);
        setTimeout(() => {
          navigate("/notes-page");
        }, 1000);
        return;
      }
    } catch (error) {
      setErr(error.message);
      setLoading2(false);
    }
  };
  useEffect(() => {
    getNote();
  }, []);

  return (
    <div className="backdrop-brightness-20  p-2 m-2 h-72  rounded ">
      <button className="mb-5">
        <FaArrowAltCircleLeft
          className="text-2xl text-yellow-500 "
          onClick={() => navigate("/notes-page")}
        />
      </button>
      <input
        value={title}
        onChange={(e) => setTitle(e.target.value)}
        type="text"
        placeholder="Title"
        className="w-full text-white bg-neutral-800 p-3 rounded mb-2"
      />
      <ReactQuill
        value={notesDescription}
        onChange={(value) => setNotesDescription(value)}
        className=" text-white bg-black mb-12 h-32"
        theme="snow"
        placeholder="write something here"
      />
      <button
        onClick={updateNotes}
        className="w-full bg-yellow-500 p-2 rounded text-black font-bold z-0 "
      >
        {loading ? "Loading..." : "Update"}
      </button>
      <button
        onClick={() => setDeletePopUp(true)}
        className="w-full bg-red-500 p-2 mt-2 rounded text-black font-bold  "
      >
        {loading2 ? "Loading..." : "Delete"}
      </button>
      {deletePopUp && (
        <div className="mx-auto relative w-[80%] text-sm -mt-40 h-40 bg-red-600 bg-opacity-80 rounded-lg p-6">
          <p className="text-white">
            Are you sure you want to delete this notes?
          </p>
          <div className="mt-7   flex items-center justify-center">
            <button
              className="bg-white p-2 w-16 rounded-lg font-semibold hover:bg-green-700 mx-2"
              onClick={deleteNotes}
            >
              Yes
            </button>
            <button
              className="bg-white p-2 w-16 rounded-lg font-semibold hover:bg-red-700 mx-2"
              onClick={() => setDeletePopUp(false)}
            >
              No
            </button>
          </div>
        </div>
      )}
      {err && (
        <div className="w-full bg-yellow-300 p-2 rounded mt-2  font-extrabold  font-mono text-black text-center">
          {err}
        </div>
      )}
    </div>
  );
};

export default AddNotePopUp;
