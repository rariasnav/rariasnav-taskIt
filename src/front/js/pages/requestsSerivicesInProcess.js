import React, {useContext, useEffect, useState} from "react";
import { Context } from "../store/appContext";
import { useNavigate } from "react-router-dom";
import { getData } from "../utils/getData";
import "../../styles/home.css";

export const RequestsServicesInProcess = () =>{
    const {actions, store} = useContext(Context)
    const navigate = useNavigate()
    const [serviceRequestOffered, setServiceRequestOffered] = useState([])
    const [inProcessRequests, setInProcessRequests] = useState([])
    const [offeredToMyUser, setOfferedToMyUser] = useState([])

    useEffect( ()=>{
        getData(actions.getServicesRequestsOffers, setServiceRequestOffered);
    },[actions])

    useEffect( ()=>{
        if(serviceRequestOffered){
            setInProcessRequests( serviceRequestOffered.filter( offered => offered.status === 'accepted' ))
        }
    },[serviceRequestOffered])

    useEffect( ()=>{
        const filterByUser = async () =>{
            if(store.loggedUser){
                setOfferedToMyUser(inProcessRequests.filter( offered => offered.user_client_id.email === store.loggedUser.email ))
            }            
        }
        filterByUser()
    },[inProcessRequests, store.loggedUser])
    
    return(        
        <div className="container">
            {store.loggedUser && store.loggedUser.role === 'client' && (
                <div className="body m-5">
                    <div className="text-center">
                        <h1 className="">Your requests in process</h1>
                    </div>
                    <div className="list-group">
                        {offeredToMyUser && 
                            offeredToMyUser.length > 0 && 
                            offeredToMyUser.map( (offered, index)=> {
                                return(
                                        <div className="request-item" key={index}>                    
                                            <div className="d-flex justify-content-between">
                                                <h3 className=" ">{offered.service_request_id.description}</h3>
                                            </div>
                                            <h4 className="tasker-name">Tasker: {offered.user_vendor_id.full_name}</h4>                        
                                            <h4 className="rate">Rate: ${offered.rate}</h4> 
                                            <div className="list-group-item-footer">
                                                <button 
                                                    type="button" 
                                                    className="btn btn-primary" 
                                                    onClick={ ()=>navigate(`/reviewProfile/${offered.user_vendor_id.id}`) }>
                                                    Review tasker
                                                </button>
                                            </div>
                                        </div>
                                    );
                                })}                    
                    </div>
                </div>
            )}
        </div>           
    )
}