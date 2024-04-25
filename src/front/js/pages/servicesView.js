import React,{useContext} from "react";
import { useNavigate } from "react-router-dom";
import { Context } from "../store/appContext";
import "../../styles/home.css";

export const ServicesView = () => {

    return(
        <div className="services-list-view">
            <div className="album py-5 bg-body-tertiary">
    			<div className="container">

					<div className="row row-cols-1 row-cols-sm-2 row-cols-md-3 g-3">
						<div className="col">
                            <div className="card" style={{width:"100%", height:"225"}}>
                                <img src="https://picsum.photos/200" className="card-img-top" alt="..."/>
                                <div className="card-body">
                                    <h5 className="card-title">Service name</h5>
                                    <p className="card-text">breef words about service</p>
                                </div>
                                <ul className="list-group list-group-flush">
                                    <li className="list-group-item">
                                        <a href="#" className="card-link">Activities related</a>
                                    </li>
                                    <li className="list-group-item">
                                        <a href="#" className="card-link">Activities related</a>
                                    </li>
                                    <li className="list-group-item">
                                        <a href="#" className="card-link">Activities related</a>
                                    </li>
                                    
                                </ul>                               
                            </div>
						</div>
						<div className="col">
                        <div className="card" style={{width:"100%", height:"225"}}>
                                <img src="https://picsum.photos/200" className="card-img-top" alt="..."/>
                                <div className="card-body">
                                    <h5 className="card-title">Service name</h5>
                                    <p className="card-text">breef words about service</p>
                                </div>
                                <ul className="list-group list-group-flush">
                                    <li className="list-group-item">
                                        <a href="#" className="card-link">Activities related</a>
                                    </li>
                                    <li className="list-group-item">
                                        <a href="#" className="card-link">Activities related</a>
                                    </li>
                                    <li className="list-group-item">
                                        <a href="#" className="card-link">Activities related</a>
                                    </li>
                                    
                                </ul>                               
                            </div>
						</div>
						<div className="col">
                        <div className="card" style={{width:"100%", height:"225"}}>
                                <img src="https://picsum.photos/200" className="card-img-top" alt="..."/>
                                <div className="card-body">
                                    <h5 className="card-title">Service name</h5>
                                    <p className="card-text">breef words about service</p>
                                </div>
                                <ul className="list-group list-group-flush">
                                    <li className="list-group-item">
                                        <a href="#" className="card-link">Activities related</a>
                                    </li>
                                    <li className="list-group-item">
                                        <a href="#" className="card-link">Activities related</a>
                                    </li>
                                    <li className="list-group-item">
                                        <a href="#" className="card-link">Activities related</a>
                                    </li>
                                    
                                </ul>                               
                            </div>
						</div>

						<div className="col">
                            <div className="card" style={{width:"100%", height:"225"}}>
                                <img src="https://picsum.photos/200" className="card-img-top" alt="..."/>
                                <div className="card-body">
                                    <h5 className="card-title">Service name</h5>
                                    <p className="card-text">breef words about service</p>
                                </div>
                                <ul className="list-group list-group-flush">
                                    <li className="list-group-item">
                                        <a href="#" className="card-link">Activities related</a>
                                    </li>
                                    <li className="list-group-item">
                                        <a href="#" className="card-link">Activities related</a>
                                    </li>
                                    <li className="list-group-item">
                                        <a href="#" className="card-link">Activities related</a>
                                    </li>
                                    
                                </ul>                               
                            </div>
						</div>
						<div className="col">
                            <div className="card" style={{width:"100%", height:"225"}}>
                                <img src="https://picsum.photos/200" className="card-img-top" alt="..."/>
                                <div className="card-body">
                                    <h5 className="card-title">Service name</h5>
                                    <p className="card-text">breef words about service</p>
                                </div>
                                <ul className="list-group list-group-flush">
                                    <li className="list-group-item">
                                        <a href="#" className="card-link">Activities related</a>
                                    </li>
                                    <li className="list-group-item">
                                        <a href="#" className="card-link">Activities related</a>
                                    </li>
                                    <li className="list-group-item">
                                        <a href="#" className="card-link">Activities related</a>
                                    </li>
                                    
                                </ul>                               
                            </div>
						</div>
						<div className="col">
                            <div className="card" style={{width:"100%", height:"225"}}>
                                <img src="https://picsum.photos/200" className="card-img-top" alt="..."/>
                                <div className="card-body">
                                    <h5 className="card-title">Service name</h5>
                                    <p className="card-text">breef words about service</p>
                                </div>
                                <ul className="list-group list-group-flush">
                                    <li className="list-group-item">
                                        <a href="#" className="card-link">Activities related</a>
                                    </li>
                                    <li className="list-group-item">
                                        <a href="#" className="card-link">Activities related</a>
                                    </li>
                                    <li className="list-group-item">
                                        <a href="#" className="card-link">Activities related</a>
                                    </li>
                                    
                                </ul>                               
                            </div>
						</div>  
					</div>
				</div>
  		</div>
        </div>
    )
}