import React, {useContext, useState, useEffect} from "react";
import { Context } from "../store/appContext";
import { useNavigate } from "react-router-dom";
import { getData } from "../utils/getData";
import "../../styles/home.css";

export const TakenRequests = () =>{
    const {actions, store} = useContext(Context)
    const navigate = useNavigate()
    const [requestsOffers, setRequestsOffers] = useState([])
    const [acceptedRequests, setAcceptedRequests] = useState([])
    const [takenByUser, setTakenByUser] = useState([])
    const [tempData, setTempData] = useState()
    const [status, setStatus] = useState({
        "service_request_status": " ",
        "service_request_offer_status": " "
    })

    const handleClick = async () =>{
        setStatus({
            "service_request_status": "pending",
            "service_request_offer_status": "pending"
        })
    }

    const sendData = async (indexes) =>{
        const result = await actions.updateServicesRequestsOffers(indexes, status)
        if( result==201 ){
            navigate('/availableRequests')
        }
    }

    useEffect( ()=>{
        getData(actions.getServicesRequestsOffers, setRequestsOffers);
    },[actions])

    useEffect( ()=>{
        if(requestsOffers){
            setAcceptedRequests(requestsOffers.filter( request => request.status === "accepted" ))
        }
    },[requestsOffers])

    useEffect( ()=>{
        const filterByUser = async () => {
            if(store.loggedUser){
                setTakenByUser(acceptedRequests.filter( taken => taken.user_vendor_id.email === store.loggedUser.email ))
            }
        }
        filterByUser()
    },[store.loggedUser, acceptedRequests])
    
    return(
        <div className="container">
            <div className="body m-5">
                <div className="text-center ">
                    <h1 className="">Offers you have taken</h1>
                </div>
                <div className="list-group">
                    {takenByUser && takenByUser.length > 0 && takenByUser.map( (taken, index)=> {
                        return(
                                <div className="list-group-item mb-3" key={index}>
                                    <div className="d-flex justify-content-between">
                                        <h3 className="text-primary-custom">{taken.service_request_id.description}</h3>
                                        <p className=" ">{taken.service_request_id.description.address}</p>
                                    </div>                            
                                    <p className="">Moving: {taken.service_request_id.moving}</p>
                                    <p className="">Tools: {taken.service_request_id.tools}</p>
                                    <button 
                                        type="button"
                                        className="btn btn-secondary"
                                        data-bs-toggle="modal" 
                                        data-bs-target="#doneRequestOfferModal"
                                        onClick={ ()=>{
                                            setTempData({
                                                "service_request_offer_id": taken.id,
                                                "service_request_id": taken.service_request_id.id
                                            });
                                            setStatus({
                                                "service_request_status": "done",
                                                "service_request_offer_status": "finished"
                                            })
                                        }}
                                        >Mark as done                                   
                                    </button>
                                    <button 
                                        type="button" 
                                        className="btn btn-danger mx-2" 
                                        data-bs-toggle="modal" 
                                        data-bs-target="#cancelRequestOfferModal"
                                        onClick={ ()=>{
                                            setTempData({
                                            "service_request_offer_id": taken.id,
                                            "service_request_id": taken.service_request_id.id
                                            });
                                            setStatus({
                                                "service_request_status": "pending",
                                                "service_request_offer_status": "pending"
                                                })
                                        }}
                                        >Cancel service
                                    </button>                        
                                </div>
                            )
                        })
                    } 
                </div>
            </div>

            <div className="modal fade" id="cancelRequestOfferModal" 
                tabIndex="-1" aria-labelledby="exampleModalLabel" aria-hidden="true">
                <div className="modal-dialog">
                    <div className="modal-content">
                        <div className="modal-header">
                            <h1 className="modal-title fs-5">Are you sure to cancel the task?</h1>
                            <button 
                                type="button" 
                                className="btn-close" 
                                data-bs-dismiss="modal" 
                                aria-label="Close">                                                                
                            </button>
                        </div>                                          
                        <div className="modal-footer">
                            <button type="button" className="btn btn-secondary" 
                            data-bs-dismiss="modal">Close</button>
                            <button type="button" className="btn btn-danger" data-bs-dismiss="modal" 
                            onClick={ ()=>sendData(tempData) }>Cancel task</button>
                        </div>
                    </div>
                </div>
            </div>

            <div className="modal fade" id="doneRequestOfferModal" 
                tabIndex="-1" aria-labelledby="exampleModalLabel" aria-hidden="true">
                <div className="modal-dialog">
                    <div className="modal-content">
                        <div className="modal-header">
                            <h1 className="modal-title fs-5">Finish service</h1>
                            <button 
                                type="button" 
                                className="btn-close" 
                                data-bs-dismiss="modal" 
                                aria-label="Close">                                                                
                            </button>
                        </div>                                          
                        <div className="modal-footer">
                            <button type="button" className="btn btn-primary" 
                            data-bs-dismiss="modal">Close</button>
                            <button type="button" className="btn btn-secondary" data-bs-dismiss="modal" 
                            onClick={ ()=>sendData(tempData) }>Finish</button>
                        </div>
                    </div>
                </div>
            </div>

        </div>
    )
}
