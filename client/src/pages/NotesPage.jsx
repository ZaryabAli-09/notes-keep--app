import React, { useState } from "react";
import Add from "../components/AddNoteBtn";
import { Link } from "react-router-dom";
import { FaArrowAltCircleLeft } from "react-icons/fa";
import AddNotePopUp from "../components/AddNotePopUp";
import Nav from "../components/Nav";
const NotesPage = () => {
  const [addNotePopUp, setAddNotePopUp] = useState(false);
  const onAddNotePopUp = () => {
    return setAddNotePopUp(!addNotePopUp);
  };
  return (
    <>
      <Nav />
      <div className="text-white">
        <div className="bg-black w-full flex items-center justify-center pb-3">
          <input
            type="text"
            className="w-3/4 bg-neutral-800 rounded-3xl text-xs p-3 pl-3 border-none outline-none"
            placeholder="Search notes"
          />
        </div>
        {addNotePopUp && (
          <button className="ml-5" onClick={() => setAddNotePopUp(false)}>
            <FaArrowAltCircleLeft className="text-xl text-yellow-400 " />
          </button>
        )}

        {addNotePopUp ? (
          <AddNotePopUp />
        ) : (
          <div className="notes p-4 flex flex-col space-y-3">
            <Link to={"/notes-details"}>
              <div className="note-1 bg-neutral-800 rounded-lg p-2">
                <h3 className="font-bold text-sm ">Personal Details</h3>
                <p className="text-sm text-neutral-400">
                  facebook password : helloqwerthuiop123....
                </p>
                <div className="font-semibold text-xs text-neutral-500">
                  April 23
                </div>
              </div>
            </Link>
            <div className="note-1 bg-neutral-800 rounded-lg p-2">
              <h3 className="font-bold text-sm ">Personal Details</h3>
              <p className="text-sm text-neutral-400">
                facebook password : helloqwerthuiop123....
              </p>
              <div className="font-semibold text-xs text-neutral-500">
                April 23
              </div>
            </div>
            <div className="note-1 bg-neutral-800 rounded-lg p-2">
              <h3 className="font-bold text-sm ">Personal Details</h3>
              <p className="text-sm text-neutral-400">
                facebook password : helloqwerthuiop123....
              </p>
              <div className="font-semibold text-xs text-neutral-500">
                April 23
              </div>
            </div>
            <div className="note-1 bg-neutral-800 rounded-lg p-2">
              <h3 className="font-bold text-sm ">Personal Details</h3>
              <p className="text-sm text-neutral-400">
                facebook password : helloqwerthuiop123....
              </p>
              <div className="font-semibold text-xs text-neutral-500">
                April 23
              </div>
            </div>
            <div className="note-1 bg-neutral-800 rounded-lg p-2">
              <h3 className="font-bold text-sm ">Personal Details</h3>
              <p className="text-sm text-neutral-400">
                facebook password : helloqwerthuiop123....
              </p>
              <div className="font-semibold text-xs text-neutral-500">
                April 23
              </div>
            </div>
            <div className="note-1 bg-neutral-800 rounded-lg p-2">
              <h3 className="font-bold text-sm ">Personal Details</h3>
              <p className="text-sm text-neutral-400">
                facebook password : helloqwerthuiop123....
              </p>
              <div className="font-semibold text-xs text-neutral-500">
                April 23
              </div>
            </div>
            <div className="note-1 bg-neutral-800 rounded-lg p-2">
              <h3 className="font-bold text-sm ">Personal Details</h3>
              <p className="text-sm text-neutral-400">
                facebook password : helloqwerthuiop123....
              </p>
              <div className="font-semibold text-xs text-neutral-500">
                April 23
              </div>
            </div>
            <div className="note-1 bg-neutral-800 rounded-lg p-2">
              <h3 className="font-bold text-sm ">Personal Details</h3>
              <p className="text-sm text-neutral-400">
                facebook password : helloqwerthuiop123....
              </p>
              <div className="font-semibold text-xs text-neutral-500">
                April 23
              </div>
            </div>
            <div className="note-1 bg-neutral-800 rounded-lg p-2">
              <h3 className="font-bold text-sm ">Personal Details</h3>
              <p className="text-sm text-neutral-400">
                facebook password : helloqwerthuiop123....
              </p>
              <div className="font-semibold text-xs text-neutral-500">
                April 23
              </div>
            </div>
            <div className="note-1 bg-neutral-800 rounded-lg p-2">
              <h3 className="font-bold text-sm ">Personal Details</h3>
              <p className="text-sm text-neutral-400">
                facebook password : helloqwerthuiop123....
              </p>
              <div className="font-semibold text-xs text-neutral-500">
                April 23
              </div>
            </div>
          </div>
        )}
        {!addNotePopUp && (
          <div className="cursor-pointer " onClick={onAddNotePopUp}>
            <Add />
          </div>
        )}
      </div>
    </>
  );
};

export default NotesPage;