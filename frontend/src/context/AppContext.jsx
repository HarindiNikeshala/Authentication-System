import { createContext, useEffect, useState } from "react";
import { toast } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";
import axios from "axios";

export const AppContent = createContext();

export const AppContextProvider = (props) => {

    const backendUrl = import.meta.env.VITE_BACKEND_URL;
    const [isLoggedin, setIsLoggedin] = useState(false);
    const [userData, setuserData] = useState(false);

    const getAuthState = async () => {
        try {
            const {data} = await axios.get(backendUrl+'/api/auth/is-auth');
            if(data.success){
                setIsLoggedin(true)
                getUserData()
            }
        } catch (error) {
            toast.error(error.message)
        }
    }

    const getUserData = async () => {
        try {
            const { data } = await axios.get(backendUrl + '/api/user/data');
            data.success ? setuserData(data.userData) : toast.error(data.message)
        } catch (error) {
            toast.error(error.message);
        }
    }

    useEffect(()=>{
        getAuthState();
    })

    const value = {
        backendUrl,
        isLoggedin, setIsLoggedin,
        userData, setuserData,
        getUserData
    }
    return (
        <AppContent.Provider value={value}>
            {props.children}
        </AppContent.Provider>
    )
}