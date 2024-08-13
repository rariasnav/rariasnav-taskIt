import React,{useContext, useEffect, useState} from "react";
import { Link } from "react-router-dom";
import { Context } from "../store/appContext";
import { getData } from "../utils/getData";
import "../../styles/home.css";

export const ServicesView = () => {
    const {store, actions} = useContext(Context)
    const [categories, setCategories] = useState([])
    const [categoriesSubcategories, setCategoriesSubcategories] = useState([])

    useEffect( ()=>{
        getData(actions.getCategories, setCategories);
    },[])

    useEffect( ()=>{
        getData(actions.getCategoriesSubcategories, setCategoriesSubcategories);   
    },[])
    
    return(
        <div className="services-list-view">
            <div className="album py-5 bg-body-tertiary">
    			<div className="container">
					<div className="row row-cols-1 row-cols-sm-2 row-cols-md-3 g-3">
                        {categories.map( (category, index)=> {
                            return(
                                <div className="col" key={index}>
                                    <div className="card" style={{width:"100%", height:"225"}} >
                                        <img src="https://picsum.photos/200" className="card-img-top" alt="..."/>
                                        <div className="card-body">
                                            <h5 className="card-title">{category.name}</h5>
                                            <p className="card-text">{category.description}</p>
                                        </div>
                                        <ul className="list-group list-group-flush">
                                            {categoriesSubcategories.filter( 
                                                categorySubcategory => categorySubcategory.service_category.name === category.name ).map( 
                                                    (filteredCategorySubcategory, index)=> {
                                                    return(
                                                        <li className="list-group-item" key={index}>
                                                            <Link to={`/postForAService/${filteredCategorySubcategory.id}`}>
                                                                <span
                                                                className="card-link">{filteredCategorySubcategory.service_subcategory.name}
                                                                </span>
                                                            </Link>
                                                        </li>
                                                    )
                                            }
                                            )}                                            
                                        </ul>                               
                                    </div>
                                </div>
                            )})}
					</div>
				</div>
  		    </div>
        </div>
    )
}